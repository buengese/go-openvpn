package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── harness ───────────────────────────────────────────────────────────────────

// newTestServer starts a relay-server on a loopback port of the kernel's
// choosing and returns it together with its address.
func newTestServer(t *testing.T) (*server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{st: newStore()}
	httpSrv := &http.Server{Handler: srv}
	go httpSrv.Serve(ln)                  //nolint:errcheck
	t.Cleanup(func() { httpSrv.Close() }) //nolint:errcheck
	return srv, ln.Addr().String()
}

// testAgent is a WebSocket client standing in for the CLI agent: it speaks the
// masked client framing the real agent speaks, and nothing else.
type testAgent struct {
	conn net.Conn
	rdr  *bufio.Reader
}

func dialAgent(t *testing.T, addr string) *testAgent {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	req := "GET /ws HTTP/1.1\r\nHost: " + addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rdr := bufio.NewReaderSize(conn, 64*1024)
	status, err := rdr.ReadString('\n')
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake: %s", strings.TrimSpace(status))
	}
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			t.Fatalf("handshake headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	a := &testAgent{conn: conn, rdr: rdr}
	t.Cleanup(a.close)
	return a
}

func (a *testAgent) close() { a.conn.Close() } //nolint:errcheck

// send writes one masked client frame, as RFC 6455 §5.3 requires of a client.
func (a *testAgent) send(t *testing.T, opcode byte, payload []byte) {
	t.Helper()
	key := [4]byte{0x0a, 0x0b, 0x0c, 0x0d}
	n := len(payload)
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	hdr = append(hdr, key[:]...)
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ key[i%4]
	}
	if err := a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.conn.Write(append(hdr, masked...)); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

func (a *testAgent) authenticate(t *testing.T, token, agentID, hostname string) {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"action": "auth", "token": token, "agent_id": agentID, "hostname": hostname,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.send(t, 0x1, b)
}

// recv reads one server→client frame. Server frames are unmasked, so the
// server's own reader handles them unchanged.
func (a *testAgent) recv(t *testing.T, timeout time.Duration) ([]byte, byte) {
	t.Helper()
	if err := a.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	payload, opcode, err := wsReadFrame(a.rdr)
	if err != nil {
		t.Fatalf("recv frame: %v", err)
	}
	return payload, opcode
}

// waitFor polls cond until it holds, and fails the test if it never does.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func postJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// ── connection teardown ───────────────────────────────────────────────────────

// TestAgentGoesOfflineWhenConnectionDrops covers the handler deadlock: the
// writer goroutine parked on the outbound channel, which only unregisterConn
// closes, and unregisterConn is deferred behind the wait for that writer. The
// agent then stays "standby" in the store for the life of the process.
func TestAgentGoesOfflineWhenConnectionDrops(t *testing.T) {
	srv, addr := newTestServer(t)

	agent := dialAgent(t, addr)
	agent.authenticate(t, "tok", "agent-offline", "host-1")
	waitFor(t, 3*time.Second, "agent registration", func() bool {
		return srv.st.getAgent("agent-offline") != nil
	})

	agent.close()

	waitFor(t, 3*time.Second, "agent to be marked offline", func() bool {
		a := srv.st.getAgent("agent-offline")
		return a != nil && a.Status == "offline" && a.ConnID == ""
	})
	if got := srv.st.listAgents("tok"); len(got) != 0 {
		t.Errorf("listAgents after disconnect = %d agents, want 0", len(got))
	}
}

// TestConnectionTeardownDoesNotLeakGoroutines covers the other half of the same
// deadlock: every connection leaked its handler goroutine, its writer goroutine
// and the hijacked net.Conn they both held.
func TestConnectionTeardownDoesNotLeakGoroutines(t *testing.T) {
	_, addr := newTestServer(t)

	// One connection first, so the HTTP server's own goroutines are up before
	// the baseline is taken.
	warmup := dialAgent(t, addr)
	warmup.authenticate(t, "tok", "agent-warmup", "host")
	warmup.close()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	const conns = 8
	for i := 0; i < conns; i++ {
		a := dialAgent(t, addr)
		a.authenticate(t, "tok", fmt.Sprintf("agent-leak-%d", i), "host")
		a.close()
	}

	// Two goroutines per connection is the leak; allow a couple of stragglers
	// from the HTTP server itself.
	want := baseline + 4
	got := runtime.NumGoroutine()
	for deadline := time.Now().Add(5 * time.Second); got > want && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		got = runtime.NumGoroutine()
	}
	if got > want {
		t.Fatalf("goroutines did not drain: baseline=%d, after %d closed connections=%d, want ≤%d",
			baseline, conns, got, want)
	}
	t.Logf("goroutines: baseline=%d, after %d closed connections=%d", baseline, conns, got)
}

// TestExecuteAfterAgentDisconnectIsRejected pins that an agent left unmarked
// after a disconnect does not let the app be told its credentials reached a
// connection that is gone.
func TestExecuteAfterAgentDisconnectIsRejected(t *testing.T) {
	srv, addr := newTestServer(t)

	agent := dialAgent(t, addr)
	agent.authenticate(t, "tok", "agent-gone", "host")
	waitFor(t, 3*time.Second, "agent registration", func() bool {
		return srv.st.getAgent("agent-gone") != nil
	})

	code, body := postJSON(t, "http://"+addr+"/api/v1/connect",
		map[string]string{"token": "tok", "agent_id": "agent-gone"})
	if code != http.StatusOK {
		t.Fatalf("connect = %d: %s", code, body)
	}
	var sess struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(body, &sess); err != nil {
		t.Fatal(err)
	}

	agent.close()
	waitFor(t, 3*time.Second, "agent to be marked offline", func() bool {
		a := srv.st.getAgent("agent-gone")
		return a != nil && a.ConnID == ""
	})

	code, body = postJSON(t, "http://"+addr+"/api/v1/session/"+sess.SessionID+"/execute",
		map[string]string{"ovpn_config": "remote vpn.example.com 443"})
	if code != http.StatusConflict {
		t.Errorf("execute after disconnect = %d, want %d: %s", code, http.StatusConflict, body)
	}
}

// ── protocol round trip ───────────────────────────────────────────────────────

// TestSessionRoundTrip walks the whole app-facing API against a connected
// agent: register, list, reserve a session, deliver phase 2, report status back
// and release.
func TestSessionRoundTrip(t *testing.T) {
	srv, addr := newTestServer(t)
	base := "http://" + addr + "/api/v1"

	agent := dialAgent(t, addr)
	agent.authenticate(t, "tok", "agent-rt", "runner-42")
	waitFor(t, 3*time.Second, "agent registration", func() bool {
		return srv.st.getAgent("agent-rt") != nil
	})

	resp, err := http.Get(base + "/agents?token=tok")
	if err != nil {
		t.Fatal(err)
	}
	var listed []struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck
	if len(listed) != 1 || listed[0].AgentID != "agent-rt" || listed[0].Hostname != "runner-42" {
		t.Fatalf("listAgents = %+v, want the one registered agent", listed)
	}

	code, body := postJSON(t, base+"/connect", map[string]string{"token": "tok", "agent_id": "agent-rt"})
	if code != http.StatusOK {
		t.Fatalf("connect = %d: %s", code, body)
	}
	var sess struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(body, &sess); err != nil {
		t.Fatal(err)
	}

	// A second reservation must be refused while the first is live.
	if code, _ := postJSON(t, base+"/connect", map[string]string{"token": "tok", "agent_id": "agent-rt"}); code != http.StatusConflict {
		t.Errorf("second connect = %d, want %d", code, http.StatusConflict)
	}

	code, body = postJSON(t, base+"/session/"+sess.SessionID+"/execute", map[string]string{
		"ovpn_config":   "remote vpn.example.com 443",
		"state_id":      "state-1",
		"saml_response": "assertion",
		"remote_ip":     "10.1.2.3",
	})
	if code != http.StatusOK {
		t.Fatalf("execute = %d: %s", code, body)
	}

	payload, opcode := agent.recv(t, 3*time.Second)
	if opcode != 0x1 {
		t.Fatalf("phase2 frame opcode = %#x, want text", opcode)
	}
	var push struct {
		Action    string            `json:"action"`
		SessionID string            `json:"session_id"`
		Payload   map[string]string `json:"payload"`
	}
	if err := json.Unmarshal(payload, &push); err != nil {
		t.Fatal(err)
	}
	if push.Action != "phase2" || push.SessionID != sess.SessionID {
		t.Errorf("push = %+v, want phase2 for %s", push, sess.SessionID)
	}
	if push.Payload["ovpn_config"] != "remote vpn.example.com 443" || push.Payload["state_id"] != "state-1" {
		t.Errorf("phase2 payload = %+v", push.Payload)
	}

	statusMsg, err := json.Marshal(map[string]string{
		"action": "status", "status": "connected", "assigned_ip": "172.16.0.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	agent.send(t, 0x1, statusMsg)
	waitFor(t, 3*time.Second, "agent status update", func() bool {
		a := srv.st.getAgent("agent-rt")
		return a != nil && a.Status == "connected" && a.AssignedIP == "172.16.0.9"
	})

	req, err := http.NewRequest(http.MethodDelete, base+"/session/"+sess.SessionID+"/release", nil)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rel.Body.Close() //nolint:errcheck
	if rel.StatusCode != http.StatusOK {
		t.Fatalf("release = %d", rel.StatusCode)
	}

	payload, _ = agent.recv(t, 3*time.Second)
	var rmsg struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(payload, &rmsg); err != nil {
		t.Fatal(err)
	}
	if rmsg.Action != "disconnect" {
		t.Errorf("release push action = %q, want disconnect", rmsg.Action)
	}
}

// ── registration ──────────────────────────────────────────────────────────────

// TestAuthFrameRejectsIncompleteRegistration keeps the auth frame the single
// place registration data arrives: the URL carries none of it, so a frame
// missing a field must not register a half-identified agent.
func TestAuthFrameRejectsIncompleteRegistration(t *testing.T) {
	srv, addr := newTestServer(t)

	agent := dialAgent(t, addr)
	agent.authenticate(t, "tok", "agent-nohost", "")

	waitFor(t, 2*time.Second, "the connection to be dropped", func() bool {
		agent.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
		_, _, err := wsReadFrame(agent.rdr)
		if err == nil {
			return false
		}
		ne, ok := err.(net.Error)
		return !ok || !ne.Timeout()
	})
	if a := srv.st.getAgent("agent-nohost"); a != nil {
		t.Errorf("agent registered despite an incomplete auth frame: %+v", a)
	}
}

// TestWSRequiresUpgradeHeader guards the 400 path: a plain GET to /ws is not a
// WebSocket client and must not be hijacked.
func TestWSRequiresUpgradeHeader(t *testing.T) {
	_, addr := newTestServer(t)
	resp, err := http.Get("http://" + addr + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /ws = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
