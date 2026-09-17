// Package testenv manages the mock openvpn3-core server for integration tests.
//
// The mock server runs as a pre-built binary: set Config.Binary to its path,
// or set the MOCK_SERVER_BIN environment variable.
//
// Usage:
//
//	func TestMain(m *testing.M) {
//	    srv, err := testenv.Start(testenv.Config{Binary: mockServerPath})
//	    if err != nil { log.Fatal(err) }
//	    defer srv.Stop()
//	    os.Exit(m.Run())
//	}
//
// The package additionally carries the OpenVPN server matrix — real,
// version-pinned OpenVPN 2.4/2.5/2.6 servers built from source and driven from
// a table (see matrix_entries.go, matrix_axes.go and matrix_server.go). It is a
// separate mechanism from the mock server above, sharing only the Docker and
// readiness-polling patterns; StartMatrix/Stop mirror Start/Stop.
//
// Tests that need one of these rigs carry the tag that names what they need —
// docker, mockserver, soak or privileged — so that `go test ./...` with no tag
// needs no Docker daemon and no fixture binary. See docs/testing.md.
// This package is test support. It is imported from outside this module by the
// private provider-sweep tool, which uses the reference oracle to arbitrate its
// live failures, and that import carries **no API stability promise**: the tool
// pins a checkout, not a version, and this package changes when the rig needs
// it to.
package testenv

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// MockServerEvent is one structured log line emitted by the mock server.
type MockServerEvent struct {
	TS     int64  `json:"ts"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
}

// AuthPacketInfo holds the non-secret metadata logged by the mock server in an
// "auth_packet_recv" event. Credential values and prefixes are never logged.
type AuthPacketInfo struct {
	TotalBytes     int    `json:"total_bytes"`
	Options        string `json:"options"`
	Username       string `json:"username"`
	PasswordLen    int    `json:"password_len"`
	CredentialKind string `json:"credential_kind"`
	PeerInfo       string `json:"peer_info"`
}

// Config controls how the mock server is started.
type Config struct {
	// CRV1Mode, when true, starts the server in AUTH_FAILED,CRV1 mode.
	CRV1Mode bool

	// RedirectGateway, when true, instructs the mock server to include
	// "redirect-gateway def1" in its PUSH_REPLY, simulating AWS Client VPN
	// full-tunnel mode. Use this to test issue #7 bypass-route behaviour.
	RedirectGateway bool

	// Binary is the path to the mock-server binary. The MOCK_SERVER_BIN
	// environment variable is used as a fallback when it is empty.
	Binary string

	// CertDir is the directory containing ca.crt, server.crt, server.key.
	// Default: resolved from the binary's location.
	CertDir string

	// TCPPort is the host-side TCP port. 0 means pick a free port.
	TCPPort int

	// KeepaliveMS overrides how often the server pushes a data-channel
	// keepalive once the tunnel is up, in milliseconds. 0 leaves the mock
	// server's own default, which is already far faster than a real server's
	// pushed ping. Lower it for a test that needs traffic in flight.
	KeepaliveMS int

	// NoKeepalive switches the server's data-channel keepalives off, for a
	// test that wants a silent peer. It takes precedence over KeepaliveMS.
	NoKeepalive bool

	// UDPPort is the host-side UDP port. 0 means pick a free port. A listener
	// is always started, because the mock server starts one unconditionally
	// and a fixed default port would collide between concurrent tests; reach
	// it through Server.UDPAddr.
	UDPPort int
}

// MockPKI is a throwaway certificate authority for the mock server, written to
// disk in the layout Config.CertDir expects.
//
// A profile with no CA is a diag.ClassConfig error rather than a silently
// unverified tunnel, so the mock-server tests are given a CA they can hand to
// the client and exercise the real certificate-verification path with.
type MockPKI struct {
	// Dir holds ca.crt, server.crt and server.key. Pass it as Config.CertDir.
	Dir string
	// CAPEM is the CA certificate, for the client profile's CA field.
	CAPEM []byte
}

// NewMockPKI generates a CA and a server key pair for the mock server and
// writes them into dir, which must already exist — t.TempDir() is the intended
// argument.
//
// The server certificate carries the serverAuth extended key usage and loopback
// IP SANs, matching what the matrix rig issues, so a profile may carry
// remote-cert-tls server without the certificate being the reason a test fails.
func NewMockPKI(dir string) (*MockPKI, error) {
	// The zero entry: no static key, no Netscape certificate-type extension,
	// nothing the mock server has an axis for.
	pki, err := newMatrixPKI(MatrixEntry{})
	if err != nil {
		return nil, fmt.Errorf("testenv: generate mock PKI: %w", err)
	}
	for name, content := range map[string]string{
		"ca.crt":     pki.CACertPEM,
		"server.crt": pki.ServerCertPEM,
		"server.key": pki.ServerKeyPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return nil, fmt.Errorf("testenv: write %s: %w", name, err)
		}
	}
	return &MockPKI{Dir: dir, CAPEM: []byte(pki.CACertPEM)}, nil
}

// Server represents a running mock server.
type Server struct {
	proc    *exec.Cmd     // the running mock server
	logPipe io.ReadCloser // its stdout, drained into events
	TCPAddr string        // "127.0.0.1:<port>"
	UDPAddr string        // "127.0.0.1:<port>"

	// mu guards events, which a goroutine appends to for as long as the
	// server runs while tests read it from their own. The field is unexported
	// for that reason: an unsynchronised read of it is a data race. Read it
	// with EventLog or AuthEvents.
	mu     sync.Mutex
	events []MockServerEvent
}

// EventLog returns a snapshot of the events logged by the server so far.
func (s *Server) EventLog() []MockServerEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// WaitForEvents blocks until the server's log holds at least n events named
// name, and returns how many it saw. It gives up after within and returns the
// count it reached, so a caller can assert on a shortfall rather than on a
// timeout.
//
// EventLog is the far end of an asynchronous pipeline — stdout line, OS pipe,
// scanner, buffered channel, appending goroutine — so a test that reads it on
// the line after acting on the client is racing all of that, and the symptom is
// a count one short that reads exactly like a lost packet. Keep the window
// generous: the point is to remove the race, not to bound the latency.
func (s *Server) WaitForEvents(name string, n int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		seen := 0
		for _, e := range s.EventLog() {
			if e.Event == name {
				seen++
			}
		}
		if seen >= n || time.Now().After(deadline) {
			return seen
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// appendEvent records one event from the server's log stream.
func (s *Server) appendEvent(e MockServerEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// Start launches the mock server and waits until it is ready.
func Start(cfg Config) (*Server, error) {
	bin := cfg.Binary
	if bin == "" {
		bin = os.Getenv("MOCK_SERVER_BIN")
	}
	if bin == "" {
		return nil, fmt.Errorf("testenv: no mock server binary: set Config.Binary or MOCK_SERVER_BIN")
	}
	return startBinary(bin, cfg)
}

// startBinary runs the mock-server binary as a subprocess.
func startBinary(binPath string, cfg Config) (*Server, error) {
	tcpPort, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("testenv: find free TCP port: %w", err)
	}
	if cfg.TCPPort != 0 {
		tcpPort = cfg.TCPPort
	}
	udpPort, err := freeUDPPort()
	if err != nil {
		return nil, fmt.Errorf("testenv: find free UDP port: %w", err)
	}
	if cfg.UDPPort != 0 {
		udpPort = cfg.UDPPort
	}

	env := os.Environ()
	env = append(env, fmt.Sprintf("MOCK_TCP_PORT=%d", tcpPort))
	env = append(env, fmt.Sprintf("MOCK_UDP_PORT=%d", udpPort))
	if cfg.CRV1Mode {
		env = append(env, "MOCK_CRV1=1")
	}
	if cfg.RedirectGateway {
		env = append(env, "MOCK_REDIRECT_GATEWAY=1")
	}
	switch {
	case cfg.NoKeepalive:
		env = append(env, "MOCK_KEEPALIVE_MS=0")
	case cfg.KeepaliveMS != 0:
		env = append(env, fmt.Sprintf("MOCK_KEEPALIVE_MS=%d", cfg.KeepaliveMS))
	}
	if cfg.CertDir != "" {
		env = append(env, "CERT_DIR="+cfg.CertDir)
	}

	cmd := exec.Command(binPath)
	cmd.Env = env

	// Capture stdout (JSON event log).
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("testenv: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("testenv: start binary: %w", err)
	}

	srv := &Server{
		proc:    cmd,
		logPipe: pipe,
		TCPAddr: fmt.Sprintf("127.0.0.1:%d", tcpPort),
		UDPAddr: fmt.Sprintf("127.0.0.1:%d", udpPort),
	}

	// Stream events in background so the pipe doesn't block.
	// waitReadyBinary consumes from this channel until "ready"; afterwards
	// the background goroutine continues draining into srv.events.
	eventsCh := make(chan MockServerEvent, 256)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			var e MockServerEvent
			if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
				eventsCh <- e
			}
		}
		close(eventsCh)
	}()

	// waitReadyBinary reads from eventsCh and populates srv.events.
	// After it returns, start a goroutine to drain remaining events.
	if err := srv.waitReadyBinary(10*time.Second, eventsCh); err != nil {
		srv.Stop() //nolint:errcheck
		return nil, fmt.Errorf("testenv: server did not become ready: %w", err)
	}
	go func() {
		for e := range eventsCh {
			srv.appendEvent(e)
		}
	}()
	return srv, nil
}

// Stop terminates the mock server.
func (s *Server) Stop() error {
	if s.proc == nil {
		return nil
	}
	s.proc.Process.Kill() //nolint:errcheck // Wait below reports what happened
	return s.proc.Wait()
}

// waitReadyBinary waits for the binary process to emit a "ready" event.
// eventsCh is the streaming channel from the binary's stdout goroutine.
func (s *Server) waitReadyBinary(timeout time.Duration, eventsCh <-chan MockServerEvent) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout waiting for ready event")
		case e, ok := <-eventsCh:
			if !ok {
				return fmt.Errorf("server stdout closed before ready event")
			}
			s.appendEvent(e)
			if e.Event == "ready" {
				return nil
			}
		}
	}
}

// AuthEvents returns all "auth_packet_recv" events logged by the server,
// parsed into AuthPacketInfo structs for easy assertion in tests.
func (s *Server) AuthEvents() []AuthPacketInfo {
	var out []AuthPacketInfo
	for _, e := range s.EventLog() {
		if e.Event != "auth_packet_recv" {
			continue
		}
		var info AuthPacketInfo
		if err := json.Unmarshal([]byte(e.Detail), &info); err == nil {
			out = append(out, info)
		}
	}
	return out
}

// freeUDPPort returns a free UDP port on localhost. Separate from freePort
// because a port being free for TCP says nothing about UDP: a mock server told
// to bind a UDP port something else holds logs a warning and serves TCP only,
// which shows up as a test that silently never reaches the server.
func freeUDPPort() (int, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port, nil
}

// freePort returns a free TCP port on localhost.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}
