package testenv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by StartMatrix. Tests are expected to distinguish
// "this entry is not implemented yet" (skip) from "the rig is broken" (fail).
var (
	// ErrUnimplemented is returned for a matrix entry the rig cannot bring
	// up yet. Enumerating tests should skip on this, not fail. The wrapped
	// message is MatrixEntry.SkipReason.
	ErrUnimplemented = errors.New("testenv: matrix entry not implemented")

	// ErrImageMissing is returned when the pinned server image for an entry
	// has not been built. Its message names the make target that builds it.
	ErrImageMissing = errors.New("testenv: matrix server image not built")
)

// MatrixReadyTimeout bounds how long StartMatrix waits for the server to log
// "Initialization Sequence Completed".
const MatrixReadyTimeout = 30 * time.Second

// matrixReadyMarker is the line OpenVPN prints once the tun device is up and
// the listener is bound. Polling for it mirrors waitReady's approach for the
// mock server.
const matrixReadyMarker = "Initialization Sequence Completed"

// MatrixLabel is applied to every container StartMatrix creates, so strays can
// be found and removed with `make matrix-clean`.
const MatrixLabel = "net.bngs.goopenvpn.testenv=matrix"

// MatrixPKI is the ephemeral certificate material generated for one matrix
// server run. It is created in memory by StartMatrix, handed to the container
// through an environment variable, and discarded when the process exits:
// nothing is written to the repository and nothing is reused between runs,
// which is what keeps credential material out of the tree.
type MatrixPKI struct {
	// CACertPEM is the throwaway CA certificate.
	CACertPEM string
	// ServerCertPEM is the server certificate, signed by the CA.
	ServerCertPEM string
	// ServerKeyPEM is the server private key.
	ServerKeyPEM string
	// ClientCertPEM is a client certificate, signed by the CA.
	ClientCertPEM string
	// ClientKeyPEM is the client private key.
	ClientKeyPEM string
	// StaticKey is an OpenVPN static key V1 file, used for tls-auth and
	// tls-crypt. Empty when the entry needs no static key.
	StaticKey string
}

// MatrixServer is a running OpenVPN server from the matrix.
type MatrixServer struct {
	// Entry is the matrix entry this server was started from.
	Entry MatrixEntry
	// Image is the exact image tag that was run.
	Image string
	// ContainerID is the Docker container ID.
	ContainerID string
	// Port is the host-side published port, the same for both address
	// families when both are published.
	Port int
	// Addr is the dialable IPv4 host address ("127.0.0.1:port"), empty for
	// an IPv6-only entry.
	Addr string
	// Addr6 is the dialable IPv6 host address ("[::1]:port"), empty for an
	// IPv4-only entry.
	Addr6 string
	// DeadPort is a host port nothing is listening on, published by nothing
	// and reserved for this run. It is the first remote of a RemoteDeadFirst
	// entry's host-side profile, and zero for every other entry.
	DeadPort int
	// PKI is the ephemeral certificate material this server was given.
	PKI MatrixPKI

	// bundle is the base64 tar the container unpacks its configuration and
	// certificates from, kept so that Resume can hand a replacement container
	// the identical one. Rebuilding it from Entry and PKI would produce the
	// same configuration but not the same bytes, and "the same server came
	// back" is the property the restart is for.
	bundle string
	// network is the per-run user-defined Docker network the container was
	// attached to, empty when it sits on the default bridge. Only IPv6
	// entries need one, because the default bridge is IPv4-only.
	network string
	// networkErr records why an IPv6 network could not be created, so the
	// reference-client self-check can skip with a useful message.
	networkErr error

	stopOnce sync.Once
	stopErr  error
}

// StartMatrix brings up the OpenVPN server described by a matrix entry and
// waits until it logs "Initialization Sequence Completed". It mirrors
// Start/Stop for the mock server: the caller is responsible for calling Stop,
// and certificate material is generated fresh for every call.
//
// The returned error wraps ErrUnimplemented for an entry the rig cannot bring
// up (skip it) and ErrImageMissing when the pinned image has not been built
// (run `make matrix-images`).
func StartMatrix(e MatrixEntry) (*MatrixServer, error) {
	if reason := e.SkipReason(); reason != "" {
		return nil, fmt.Errorf("%w: %s: %s", ErrUnimplemented, e.Name, reason)
	}

	image, ok := ImageFor(e.Version)
	if !ok {
		return nil, fmt.Errorf("%w: %s: no image pinned for OpenVPN %s",
			ErrUnimplemented, e.Name, e.Version)
	}
	if err := requireImage(image); err != nil {
		return nil, err
	}

	pki, err := newMatrixPKI(e)
	if err != nil {
		return nil, fmt.Errorf("testenv: generate matrix PKI: %w", err)
	}

	bundle, err := matrixBundle(e, pki)
	if err != nil {
		return nil, fmt.Errorf("testenv: build config bundle: %w", err)
	}

	port, err := freeMatrixPort(e.Proto)
	if err != nil {
		return nil, fmt.Errorf("testenv: find free host port: %w", err)
	}

	// The dead first remote of a failover entry: probed the same way the live
	// port is and then never bound, so it is free when the profile is written
	// and belongs to nothing afterwards. A fixed number would make the entry
	// pass or fail on whatever else happens to be running.
	deadPort := 0
	if e.Remotes == RemoteDeadFirst {
		deadPort, err = freeMatrixPort(e.Proto)
		if err != nil {
			return nil, fmt.Errorf("testenv: find a dead host port: %w", err)
		}
	}

	srv := &MatrixServer{
		Entry: e, Image: image, Port: port, DeadPort: deadPort, PKI: pki, bundle: bundle,
	}
	if e.Family != AFInet {
		// Docker's default bridge network is IPv4-only, so an IPv6 entry needs
		// a throwaway user-defined network. Failing to create one is not fatal
		// — the container still binds :: and the host-side [::1] publish still
		// reaches it — but the container-to-container self-check must skip.
		if netName, nerr := createMatrixNetwork(); nerr != nil {
			srv.networkErr = nerr
		} else {
			srv.network = netName
		}
	}
	if e.Family != AFInet6 {
		srv.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	if e.Family != AFInet {
		srv.Addr6 = fmt.Sprintf("[::1]:%d", port)
	}

	if err := srv.launch(); err != nil {
		_ = srv.Stop()
		return nil, err
	}
	return srv, nil
}

// launch runs one container for this server and waits until it logs
// "Initialization Sequence Completed". It is the half of StartMatrix that
// Resume repeats, and it works from fields rather than arguments so that a
// replacement container cannot differ from the original in anything the client
// can see: the same image, bundle, published port and network.
func (s *MatrixServer) launch() error {
	transport := s.Entry.Proto.String()
	args := []string{
		"run", "-d",
		"--label", MatrixLabel,
		"--cap-add=NET_ADMIN",
		"--device=/dev/net/tun",
		"-e", "OVPN_BUNDLE_B64=" + s.bundle,
	}
	if s.network != "" {
		args = append(args, "--network", s.network)
	}
	if s.Entry.Family != AFInet6 {
		args = append(args, "-p",
			fmt.Sprintf("127.0.0.1:%d:%d/%s", s.Port, ContainerPort, transport))
	}
	if s.Entry.Family != AFInet {
		args = append(args, "-p",
			fmt.Sprintf("[::1]:%d:%d/%s", s.Port, ContainerPort, transport))
	}
	args = append(args, s.Image)

	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("testenv: docker run %s: %w (output: %s)",
			s.Entry.Name, err, strings.TrimSpace(string(out)))
	}
	s.ContainerID = strings.TrimSpace(string(out))

	if err := s.waitReadyMatrix(MatrixReadyTimeout); err != nil {
		logs, _ := s.Logs()
		return fmt.Errorf("testenv: matrix entry %s did not become ready: %w\n--- container logs ---\n%s",
			s.Entry.Name, err, TailLines(logs, 40))
	}
	return nil
}

// freeMatrixPort returns a host port that is free for the given transport.
// freePort only ever probes TCP, which would hand a UDP matrix entry a port
// another process is already using for UDP; this probes the protocol that will
// actually be published.
func freeMatrixPort(p Proto) (int, error) {
	if p == ProtoTCP {
		return freePort()
	}
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	return port, conn.Close()
}

// requireImage verifies the pinned image exists locally. It never pulls: these
// images are built from source locally and there is nothing to pull from.
func requireImage(image string) error {
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		return fmt.Errorf("%w: %s\n\tbuild it with:  make matrix-images\n\t(or: bash docker/openvpn-server/build.sh)",
			ErrImageMissing, image)
	}
	return nil
}

// Stop removes the container and any throwaway network created for it. It is
// safe to call more than once.
func (s *MatrixServer) Stop() error {
	s.stopOnce.Do(func() {
		if s.ContainerID != "" {
			out, err := exec.Command("docker", "rm", "-f", s.ContainerID).CombinedOutput()
			if err != nil {
				s.stopErr = fmt.Errorf("testenv: docker rm -f %s: %w (output: %s)",
					s.ContainerID[:12], err, strings.TrimSpace(string(out)))
			}
		}
		if s.network != "" {
			out, err := exec.Command("docker", "network", "rm", s.network).CombinedOutput()
			if err != nil && s.stopErr == nil {
				s.stopErr = fmt.Errorf("testenv: docker network rm %s: %w (output: %s)",
					s.network, err, strings.TrimSpace(string(out)))
			}
		}
	})
	return s.stopErr
}

// ---- Breaking the link ---------------------------------------------------
//
// StartMatrix and Stop are the whole life of a matrix server, which is enough
// for a test that measures a handshake and not one that measures what happens
// after it. A reconnect acceptance needs the server to go away underneath a
// connected client and come back at the same address; a client whose remote no
// longer resolves exercises its profile, not its reconnect loop.

// Interrupt removes the running container and keeps everything that made it
// addressable — the published port, the certificate material and the exact
// config bundle all stay with the MatrixServer, so Resume can put an identical
// server back at the same address.
//
// Between the two calls nothing is listening on Port, which is what a broken
// link looks like from the client's side. The session goes with the container,
// so what comes back is a server that has never heard of this client — the
// honest version of an endpoint that restarted.
//
// The throwaway IPv6 network, for an entry that needed one, is left in place
// and Resume reattaches to it: recreating it would renumber the container and
// change the address the test asserts stays the same.
//
// Interrupt, Resume and Restart are not safe to call concurrently with each
// other or with Logs, ContainerIP, ContainerProfile and the rest, all of which
// address the container by the id these replace.
func (s *MatrixServer) Interrupt() error {
	if s.ContainerID == "" {
		return nil
	}
	out, err := exec.Command("docker", "rm", "-f", s.ContainerID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("testenv: docker rm -f %s: %w (output: %s)",
			s.ContainerID[:12], err, strings.TrimSpace(string(out)))
	}
	s.ContainerID = ""
	return nil
}

// Resume brings a replacement container up from the same image, the same
// config bundle and the same certificate material, published on the same host
// port, and waits until it logs "Initialization Sequence Completed".
//
// It is a new container rather than a `docker start`, because Interrupt
// removed the old one. What the client has to find again is the address, which
// is the published port; nothing else about the container needs to survive.
func (s *MatrixServer) Resume() error {
	if s.ContainerID != "" {
		return fmt.Errorf("testenv: Resume %s: already running as %s",
			s.Entry.Name, s.ContainerID[:12])
	}
	return s.launch()
}

// Restart is Interrupt followed by Resume: by the time it returns the server
// is answering again at the address it was.
//
// A caller that needs the link to stay down for a measurable while calls the
// two halves itself and chooses the gap.
func (s *MatrixServer) Restart() error {
	if err := s.Interrupt(); err != nil {
		return err
	}
	return s.Resume()
}

// createMatrixNetwork creates a throwaway IPv6-enabled Docker network with a
// random ULA prefix, so concurrent matrix servers cannot collide.
func createMatrixNetwork() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := "go-openvpn-matrix-" + hex.EncodeToString(b[:4])
	subnet := fmt.Sprintf("fd00:4f4c:5650:%02x%02x::/64", b[4], b[5])

	out, err := exec.Command("docker", "network", "create",
		"--label", MatrixLabel,
		"--ipv6", "--subnet", subnet, name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("testenv: docker network create %s: %w (output: %s)",
			name, err, strings.TrimSpace(string(out)))
	}
	return name, nil
}

// Logs returns the container's combined stdout and stderr.
func (s *MatrixServer) Logs() (string, error) {
	if s.ContainerID == "" {
		return "", nil
	}
	out, err := containerLogs(s.ContainerID)
	if err != nil {
		return out, fmt.Errorf("testenv: docker logs: %w", err)
	}
	return out, nil
}

// DialAddr returns the address a client should dial: the IPv4 address when the
// entry publishes one, otherwise the IPv6 address.
func (s *MatrixServer) DialAddr() string {
	if s.Addr != "" {
		return s.Addr
	}
	return s.Addr6
}

// ClientProfile returns the .ovpn profile matching this running server,
// generated from the same MatrixEntry as its server configuration.
//
// The profile is for a client running on the host — ours. An AuthUserPass entry
// therefore gets the bare auth-user-pass directive with no file behind it,
// because the credentials reach our client through its API rather than its
// profile; a containerised stock client needs the file form and gets it from
// ContainerProfile.
//
// A CAFile entry's profile names its CA by bare base name, which resolves
// beside the profile. Use WriteClientProfile to put both on disk together; this
// method returns the text alone and cannot create the file it references.
func (s *MatrixServer) ClientProfile() string {
	remote := "127.0.0.1"
	if s.Addr == "" {
		remote = "::1"
	}
	return s.Entry.ClientProfile(ClientProfileOptions{
		Remote:         remote,
		Port:           s.Port,
		CACertPEM:      s.PKI.CACertPEM,
		ClientCertPEM:  s.PKI.ClientCertPEM,
		ClientKeyPEM:   s.PKI.ClientKeyPEM,
		StaticKey:      s.PKI.StaticKey,
		CAFile:         MatrixCAFile,
		DeadRemotePort: s.DeadPort,
	})
}

// ClientProfileSideFiles returns the files a host-side profile from
// ClientProfile references, keyed by the base name the profile names them
// under. Only a CAFile entry has any; every other profile is self-contained.
func (s *MatrixServer) ClientProfileSideFiles() map[string]string {
	if s.Entry.CASource != CAFile {
		return nil
	}
	return map[string]string{MatrixCAFile: s.PKI.CACertPEM}
}

// WriteClientProfile writes the host-side client profile and every file it
// references into dir, and returns the path of the profile.
//
// A profile that names a file is only usable as a pair, and a caller
// reconstructing that pair by hand can get the file name wrong — which shows up
// as our client refusing a profile the rig generated correctly.
//
// dir is not created and is not cleaned up; pass t.TempDir().
func (s *MatrixServer) WriteClientProfile(dir string) (string, error) {
	for name, body := range s.ClientProfileSideFiles() {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return "", fmt.Errorf("testenv: write %s: %w", name, err)
		}
	}
	path := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(path, []byte(s.ClientProfile()), 0o600); err != nil {
		return "", fmt.Errorf("testenv: write client.ovpn: %w", err)
	}
	return path, nil
}

// waitReadyMatrix polls the container log until OpenVPN reports that it is up,
// mirroring waitReady's polling approach for the mock server. It gives up early
// if the container has already exited.
func (s *MatrixServer) waitReadyMatrix(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout after %s waiting for %q", timeout, matrixReadyMarker)
		case <-time.After(100 * time.Millisecond):
		}

		logs, err := s.Logs()
		if err == nil && strings.Contains(logs, matrixReadyMarker) {
			return nil
		}
		if !containerRunning(s.ContainerID) {
			return fmt.Errorf("container exited before %q", matrixReadyMarker)
		}
	}
}

// TailLines returns at most n trailing lines of s.
func TailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
