// Package relay implements the CLI agent side of the go-openvpn SAML relay protocol.
//
// An agent opens a persistent outbound WebSocket to the relay server, registers with
// its organisation token, then stands by. When the mobile/desktop app completes the
// full SAML auth flow (Phase 1 + browser), it sends the credentials to the relay which
// pushes them here via the WebSocket. The agent executes Phase 2 and brings up the tunnel.
//
// The relay server is only ever a delivery channel. This package never handles Phase 1
// or the SAML browser flow — those run entirely on the user's app.
//
// Usage:
//
//	agent, err := relay.New(relay.Config{
//	    Token:    "kjewoijo23823",
//	    Hostname: "build-runner-42",
//	    Endpoint: "wss://ws.relay.openlawsvpn.com",
//	    OnPhase2: func(ctx context.Context, p relay.Phase2Payload) error {
//	        // p carries everything vpn.SetRelayPhase2 + ConnectPhase2 need
//	        return runVPN(ctx, p)
//	    },
//	})
//	err = agent.Run(ctx) // blocks; reconnects on transient failures
package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// protocolVersion is included in every agent→server message so the backend can
// serve mixed old/new agents safely during rolling deployments.
const protocolVersion = 1

// maxMessageBytes bounds one message from the relay, fragments included.
//
// The largest legitimate one is a phase2 envelope: an .ovpn config, which
// profile bounds at 1 MiB for the files it names, alongside a SAML assertion,
// which AWS bounds at 128 KiB — both JSON-escaped inside it. The bound is here
// because the length is chosen by the peer rather than by us: without it, ten
// bytes of header declaring 1 GiB allocate 1 GiB before a payload byte arrives.
const maxMessageBytes = 4 << 20

// readPollInterval is how long a read blocks before waking to look at ctx.
//
// It is a cancellation poll, not a liveness timeout, so a read that expires
// having delivered nothing is retried wherever in a frame it happens. Noticing
// a peer that has gone away is left to TCP, which reports it as a real error.
const readPollInterval = 2 * time.Second

// writeTimeout bounds one frame write. A caller's own deadline replaces it
// when that is the nearer of the two.
const writeTimeout = 10 * time.Second

const (
	// initialBackoff is the first reconnect delay, and the one a connection
	// that worked returns to.
	initialBackoff = time.Second
	// maxBackoff caps the reconnect delay. Run's doc comment promises it.
	maxBackoff = 60 * time.Second
	// backoffResetAfter is how long a connection has to stand for the outage
	// that follows it to count as a new one rather than a continuation.
	backoffResetAfter = maxBackoff
)

// Phase2Payload is the credential bundle delivered by the relay server.
// It contains everything the agent needs to execute OpenVPN Phase 2.
type Phase2Payload struct {
	SessionID    string `json:"session_id"`
	StateID      string `json:"state_id"`
	SAMLResponse string `json:"saml_response"`
	RemoteIP     string `json:"remote_ip"`
	OvpnConfig   string `json:"ovpn_config"`
}

// Config holds agent registration parameters.
type Config struct {
	// Token is the organisation identifier/token this agent registers with.
	// Private organisation tokens act as bearer credentials; "default" is the
	// intentionally public demo organisation.
	Token string
	// Hostname is a human-readable label for this agent (defaults to os.Hostname).
	Hostname string
	// AgentID is a stable UUID identifying this agent across reconnects.
	// If empty, a random one is generated and retained for the lifetime of this Agent.
	AgentID string
	// Endpoint is the relay WebSocket URL, e.g. "wss://ws.relay.openlawsvpn.com".
	Endpoint string
	// OnPhase2 is called with the credential payload when the relay delivers one.
	// It should block until the VPN tunnel is established (or fails).
	// It must be safe to call concurrently with Run.
	OnPhase2 func(ctx context.Context, p Phase2Payload) error
	// OnDisconnect is called when the relay server requests the agent to disconnect.
	// The agent should tear down any active VPN tunnel. May be nil.
	OnDisconnect func()
	// Log receives diagnostic messages. Defaults to no-op if nil.
	Log func(msg string)
}

// Agent is a running relay agent.
type Agent struct {
	cfg      Config
	agentID  string
	endpoint *url.URL // parsed once by New; every dial reuses it

	mu     sync.Mutex
	connWS *wsConn // current WebSocket connection (nil when disconnected)
}

// New creates a new Agent. It does not connect; call Run to start.
func New(cfg Config) (*Agent, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("relay: token is required")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("relay: endpoint is required")
	}
	if cfg.OnPhase2 == nil {
		return nil, fmt.Errorf("relay: OnPhase2 callback is required")
	}
	// An endpoint that can never be dialled is a configuration error, and worth
	// saying so once here rather than once per reconnect for as long as the
	// process runs.
	endpoint, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	id := cfg.AgentID
	if id == "" {
		id = newUUID()
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	return &Agent{cfg: cfg, agentID: id, endpoint: endpoint}, nil
}

// Run connects to the relay server and keeps the connection alive until ctx is
// cancelled. It reconnects automatically on transient failures with exponential
// backoff (1s → 2s → 4s … capped at 60s), starting over at 1s once a connection
// has stood for a minute.
func (a *Agent) Run(ctx context.Context) error {
	var backoff time.Duration
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.cfg.Log(fmt.Sprintf("relay: connecting to %s", a.cfg.Endpoint))
		started := time.Now()
		err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		backoff = nextBackoff(backoff, time.Since(started))
		a.cfg.Log(fmt.Sprintf("relay: disconnected (%v), retrying in %s", err, backoff))
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// nextBackoff returns how long to wait before reconnecting, given the delay
// already waited and how long the connection that just ended had stood.
//
// A connection that outlived the longest retry delay was plainly not part of the
// outage that preceded it, so the next one starts over at initialBackoff. The
// doubling is capped at maxBackoff, which Run's doc comment promises.
func nextBackoff(previous, uptime time.Duration) time.Duration {
	if previous <= 0 || uptime >= backoffResetAfter {
		return initialBackoff
	}
	return min(2*previous, maxBackoff)
}

// runOnce connects, registers, and reads messages until the connection breaks.
func (a *Agent) runOnce(ctx context.Context) error {
	ws, err := dialWS(ctx, a.endpoint)
	if err != nil {
		return fmt.Errorf("relay: dial: %w", err)
	}
	defer ws.close()

	// Send auth frame first — token travels in the WS body, not in the URL,
	// so it does not appear in API Gateway access logs.
	authMsg := map[string]any{
		"version":  protocolVersion,
		"action":   "auth",
		"token":    a.cfg.Token,
		"agent_id": a.agentID,
		"hostname": a.cfg.Hostname,
	}
	authBytes, _ := json.Marshal(authMsg)
	if err := ws.sendText(ctx, authBytes); err != nil {
		return fmt.Errorf("relay: send auth: %w", err)
	}

	a.mu.Lock()
	a.connWS = ws
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.connWS = nil
		a.mu.Unlock()
	}()

	a.cfg.Log(fmt.Sprintf("relay: registered — agent_id=%s hostname=%s", a.agentID, a.cfg.Hostname))

	// Ping loop keeps the WS alive through NAT/firewall idle timeouts.
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := ws.sendPing(ctx); err != nil {
					return
				}
			case <-ctx.Done():
				return
			case <-ws.closed:
				return
			}
		}
	}()

	for {
		msg, err := ws.readMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Graceful shutdown: tell the relay we are going offline so the
				// app sees the correct status immediately instead of waiting for
				// the server to detect the dropped TCP connection.
				bgCtx := context.Background()
				a.sendStatus(bgCtx, "", "offline", "")
			}
			ws.close() // unblock the ping goroutine immediately
			<-pingDone
			return err
		}
		if err := a.handleMessage(ctx, msg); err != nil {
			a.cfg.Log(fmt.Sprintf("relay: message handler error: %v", err))
		}
	}
}

func (a *Agent) handleMessage(ctx context.Context, msg []byte) error {
	var envelope struct {
		Version   int             `json:"version"`
		Action    string          `json:"action"`
		SessionID string          `json:"session_id"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		return fmt.Errorf("relay: unmarshal envelope: %w", err)
	}

	switch envelope.Action {
	case "phase2":
		var p Phase2Payload
		if err := json.Unmarshal(envelope.Payload, &p); err != nil {
			return fmt.Errorf("relay: unmarshal phase2 payload: %w", err)
		}
		p.SessionID = envelope.SessionID
		a.cfg.Log(fmt.Sprintf("relay: received phase2 for session %s", p.SessionID))
		go func() {
			if err := a.cfg.OnPhase2(ctx, p); err != nil {
				a.cfg.Log(fmt.Sprintf("relay: phase2 error: %v", err))
				a.sendStatus(ctx, p.SessionID, "error", "")
			}
		}()

	case "disconnect":
		a.cfg.Log("relay: server requested disconnect")
		if a.cfg.OnDisconnect != nil {
			a.cfg.OnDisconnect()
		}

	default:
		a.cfg.Log(fmt.Sprintf("relay: unknown action %q", envelope.Action))
	}
	return nil
}

// SendStatus sends a status heartbeat to the relay server.
// status is one of: "connecting", "connected", "error".
func (a *Agent) SendStatus(ctx context.Context, sessionID, status, assignedIP string) {
	a.sendStatus(ctx, sessionID, status, assignedIP)
}

func (a *Agent) sendStatus(ctx context.Context, sessionID, status, assignedIP string) {
	a.mu.Lock()
	ws := a.connWS
	a.mu.Unlock()
	if ws == nil {
		return
	}
	msg := map[string]any{
		"version":     protocolVersion,
		"action":      "status",
		"session_id":  sessionID,
		"org":         a.cfg.Token,
		"agent_id":    a.agentID,
		"status":      status,
		"assigned_ip": assignedIP,
	}
	b, _ := json.Marshal(msg)
	_ = ws.sendText(ctx, b)
}

// AgentID returns the stable agent identifier used for registration.
func (a *Agent) AgentID() string { return a.agentID }

// ---------------------------------------------------------------------------
// Minimal RFC 6455 WebSocket client (no external dependency)
// ---------------------------------------------------------------------------

// wsConn wraps a raw TCP connection and speaks RFC 6455 WebSocket framing.
// Only text frames and ping/pong are supported — sufficient for the relay protocol.
type wsConn struct {
	conn   net.Conn
	rdr    *bufio.Reader
	mu     sync.Mutex // guards writes
	closed chan struct{}
	once   sync.Once
}

// dialWS opens the WebSocket to an endpoint parseEndpoint has already checked,
// which is why the scheme is a two-way choice here rather than a validation.
func dialWS(ctx context.Context, u *url.URL) (*wsConn, error) {
	host := u.Hostname()
	port := u.Port()
	tlsEnabled := u.Scheme == "wss"
	if port == "" {
		if tlsEnabled {
			port = "443"
		} else {
			port = "80"
		}
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{}
	var rawConn net.Conn
	var err error
	if tlsEnabled {
		rawConn, err = dialTLS(ctx, addr, host)
		if err != nil {
			return nil, err
		}
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
	}

	// WebSocket handshake.
	key := wsKey()
	path := u.RequestURI()
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key,
	)
	if _, err := io.WriteString(rawConn, req); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake write: %w", err)
	}

	rdr := bufio.NewReaderSize(rawConn, 64*1024)
	status, err := rdr.ReadString('\n')
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake read: %w", err)
	}
	if !strings.Contains(status, "101") {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake rejected: %s", strings.TrimSpace(status))
	}
	// Drain remaining headers.
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("relay: WS headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}

	return &wsConn{conn: rawConn, rdr: rdr, closed: make(chan struct{})}, nil
}

func (w *wsConn) close() {
	w.once.Do(func() {
		close(w.closed)
		w.conn.Close()
	})
}

// readFull fills buf, renewing the read deadline before every attempt and
// retrying the ones that expire having delivered nothing.
//
// The deadline is per attempt, not per frame: everything after the header would
// otherwise have to arrive inside what is left of one interval, so a small frame
// spread over a few seconds fails outright and credential delivery aborts
// mid-phase2 on a slow link. A retry resumes where the short read stopped rather
// than restarting the frame, which would read the rest of it as garbage.
func (w *wsConn) readFull(ctx context.Context, buf []byte) error {
	for n := 0; n < len(buf); {
		if err := ctx.Err(); err != nil {
			return err
		}
		w.conn.SetReadDeadline(time.Now().Add(readPollInterval)) //nolint:errcheck
		got, err := w.rdr.Read(buf[n:])
		n += got
		if err == nil {
			continue
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return err
	}
	return nil
}

// readMessage reads one complete WebSocket message and returns its payload.
// Reassembles fragmented messages (FIN=0 frames), handles control frames
// (ping/pong/close), and skips empty data frames used as keepalives.
func (w *wsConn) readMessage(ctx context.Context) ([]byte, error) {
	var msg []byte // accumulated message payload across fragments

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		header := make([]byte, 2)
		if err := w.readFull(ctx, header); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("relay: read frame header: %w", err)
		}

		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0F
		declared := uint64(header[1] & 0x7F)

		switch declared {
		case 126:
			ext := make([]byte, 2)
			if err := w.readFull(ctx, ext); err != nil {
				return nil, fmt.Errorf("relay: read 16-bit length: %w", err)
			}
			declared = uint64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if err := w.readFull(ctx, ext); err != nil {
				return nil, fmt.Errorf("relay: read 64-bit length: %w", err)
			}
			// All 64 bits, judged below rather than truncated: reading only the
			// low four bytes turned a declared 2^32 into a zero-length frame and
			// a declared 2^32+n into an n-byte one, silently.
			declared = binary.BigEndian.Uint64(ext)
		}

		// Both bounds are checked before anything is allocated: the frame on its
		// own, and the message it is a fragment of.
		if declared > maxMessageBytes {
			return nil, fmt.Errorf("relay: frame declares %d bytes, over the %d-byte bound",
				declared, maxMessageBytes)
		}
		if total := uint64(len(msg)) + declared; total > maxMessageBytes {
			return nil, fmt.Errorf("relay: fragmented message reaches %d bytes, over the %d-byte bound",
				total, maxMessageBytes)
		}

		masked := header[1]&0x80 != 0
		var maskKey [4]byte
		if masked {
			if err := w.readFull(ctx, maskKey[:]); err != nil {
				return nil, fmt.Errorf("relay: read mask key: %w", err)
			}
		}

		payload := make([]byte, declared)
		if err := w.readFull(ctx, payload); err != nil {
			return nil, fmt.Errorf("relay: read payload: %w", err)
		}
		if masked {
			for i, b := range payload {
				payload[i] = b ^ maskKey[i%4]
			}
		}

		switch opcode {
		case 0x0: // continuation frame
			msg = append(msg, payload...)
			if fin {
				if len(msg) == 0 {
					msg = nil
					continue // empty fragmented message — keepalive
				}
				result := msg
				msg = nil
				return result, nil
			}
		case 0x1, 0x2: // text or binary — start of a new message
			if fin {
				if len(payload) == 0 {
					continue // empty single-frame message — keepalive
				}
				return payload, nil
			}
			// First fragment: accumulate payload; continuation frames append.
			msg = append(msg[:0], payload...)
		case 0x8: // close
			return nil, fmt.Errorf("relay: server closed connection")
		case 0x9: // ping — reply with pong
			_ = w.sendFrame(ctx, 0xA, payload)
		case 0xA: // pong — ignore
		}
	}
}

func (w *wsConn) sendText(ctx context.Context, payload []byte) error {
	return w.sendFrame(ctx, 0x1, payload)
}

func (w *wsConn) sendPing(ctx context.Context) error {
	return w.sendFrame(ctx, 0x9, nil)
}

func (w *wsConn) sendFrame(ctx context.Context, opcode byte, payload []byte) error {
	// The caller's ctx is read here: an abandoned attempt puts nothing more on
	// the wire, and a caller's own deadline, when it is the nearer one, replaces
	// the default. The graceful-shutdown status in runOnce deliberately passes a
	// background ctx, which is what lets it send after cancellation.
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Client frames must be masked (RFC 6455 §5.3).
	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		panic(fmt.Sprintf("relay: crypto/rand unavailable: %v", err))
	}

	n := len(payload)
	var header []byte
	header = append(header, 0x80|opcode) // FIN + opcode

	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n < 65536:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	header = append(header, maskKey[:]...)

	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}

	deadline := time.Now().Add(writeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	w.conn.SetWriteDeadline(deadline) //nolint:errcheck
	if _, err := w.conn.Write(append(header, masked...)); err != nil {
		return fmt.Errorf("relay: write frame: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseEndpoint parses and checks the relay WebSocket endpoint.
//
// All registration data (token, hostname, agent_id) is sent in the auth frame,
// not in the URL, so nothing sensitive appears in server-side access logs — the
// endpoint is returned as it was given, host and path included. The scheme is
// judged here rather than at the dial, so a mistyped endpoint is a refusal at
// New rather than a connection error once per reconnect attempt.
func parseEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("relay: parse endpoint %q: %w", endpoint, err)
	}
	switch u.Scheme {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("relay: endpoint %q has scheme %q, want ws or wss", endpoint, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("relay: endpoint %q has no host", endpoint)
	}
	return u, nil
}

// newUUID returns a cryptographically random UUID v4 string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("relay: crypto/rand unavailable: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// wsKey returns a random base64 Sec-WebSocket-Key value (RFC 6455 §4.1).
func wsKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("relay: crypto/rand unavailable: %v", err))
	}
	return base64.StdEncoding.EncodeToString(b[:])
}
