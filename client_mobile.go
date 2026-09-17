//go:build android || darwin

// The gomobile binding: MobileClient and MobileCallbacks.
//
// gomobile bind compiles with GOOS=android for the .aar and GOOS=ios for the
// xcframework, and GOOS=darwin builds the macOS variant; Go satisfies the
// darwin constraint under GOOS=ios too, so "android || darwin" is exactly
// those three. Desktop builds exclude the file to keep MobileClient out of the
// Linux library's API.
//
// gomobile bind requires that exported types use only basic types and slices;
// channels, maps and function values do not cross the language boundary. That
// is why this file exists: it wraps the Client API into a type that
// communicates in strings — JSON for structured data, plain error strings for
// failures.
package vpn

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/device/fd"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// MobileCallbacks is a gomobile interface implemented by the host platform.
//
// gomobile generates a Java interface from this for Android and an Objective-C
// protocol for iOS and macOS; the implementation is passed to NewMobileClient.
type MobileCallbacks interface {
	// Protect excludes the socket identified by fd from VPN routing:
	// VpnService.protect(fd) on Android, NEPacketTunnelProvider.socketProtect
	// on iOS and macOS. Must return true on success, false on failure.
	Protect(fd int) bool

	// EstablishTUN is called with the VPN network config as a JSON string
	// (see device/fd.IfconfigJSON for the schema) and the negotiated MTU. The
	// implementation builds the interface — VpnService.Builder and establish()
	// on Android, setTunnelNetworkSettings and packetFlow on iOS and macOS —
	// and returns the file descriptor, or -1 on failure.
	EstablishTUN(ifconfigJSON string, mtu int) int

	// Log receives diagnostic log messages from the Go layer.
	Log(message string)
}

// MobileClient is a gomobile-compatible VPN client.
//
// Which methods a profile needs depends on how it authenticates:
//
//	certificate    connect()
//	federated      startSAMLFlow(), open the URL, then completeSAMLFlow(token)
//
// From Android/Kotlin, a federated profile:
//
//	val mc = Vpn.newMobileClient(profile.configContent, callbacks)
//	val result = mc.startSAMLFlow()
//	if (result.startsWith("{")) {
//	    val samlURL = JSONObject(result).getString("saml_url")
//	    // open samlURL in a browser, collect the SAMLResponse
//	    val err = mc.completeSAMLFlow(samlToken)
//	    if (err.isNotEmpty()) { return }
//	} else if (result.isNotEmpty()) { return }
type MobileClient struct {
	inner  *Client
	ctx    context.Context
	cancel context.CancelFunc
	cb     MobileCallbacks
}

// NewMobileClient creates a MobileClient from the .ovpn profile content string.
// cb may be nil (callbacks are skipped — useful on Linux for testing). Panics,
// which gomobile turns into a Java exception, if the profile cannot be parsed.
func NewMobileClient(profileContent string, cb MobileCallbacks) *MobileClient {
	p, err := profile.ParseString(profileContent)
	if err != nil {
		// gomobile converts Go panics to Java exceptions.
		panic("vpn: NewMobileClient: " + err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := New(p)

	if cb != nil {
		c.ProtectFn = func(fd int) error {
			if !cb.Protect(fd) {
				return fmt.Errorf("vpn: Protect(%d) returned false", fd)
			}
			return nil
		}

		// The host owns addressing, routes and DNS, so the fd backend installs
		// nothing. Establish runs once the PUSH_REPLY is parsed — the earliest
		// point the host has what it needs to build the interface.
		c.Device = &fd.Backend{
			Establish: func(_ context.Context, p device.Params) (int, error) {
				ifconfigJSON := fd.IfconfigJSON(p.Push, p.DNS, p.MTU)
				cb.Log(fmt.Sprintf("vpn: establishing TUN, config=%s", ifconfigJSON))
				return cb.EstablishTUN(ifconfigJSON, p.MTU), nil
			},
		}

		c.EventFn = func(e Event) {
			switch e.Type {
			case EventLog:
				cb.Log(e.Message)
			case EventStateChanged:
				if e.Message != "" {
					cb.Log(fmt.Sprintf("vpn: state → %s: %s", e.State, e.Message))
				} else {
					cb.Log(fmt.Sprintf("vpn: state → %s", e.State))
				}
			}
		}
	}

	return &MobileClient{
		inner:  c,
		ctx:    ctx,
		cancel: cancel,
		cb:     cb,
	}
}

// Connect dials, authenticates, and brings up the VPN tunnel. It is the whole
// connection for a certificate profile; a federated profile needs a browser in
// the middle, which the host runs itself.
//
// Returns "" on success, or an error description on failure.
func (m *MobileClient) Connect() string {
	if err := m.inner.Connect(m.ctx); err != nil {
		return err.Error()
	}
	return ""
}

// StartSAMLFlow dials the server and authenticates as far as it can without a
// browser. A certificate or username/password profile needs none of it: call
// Connect, which is the same work without the split.
//
// Return values:
//   - JSON object {"saml_url":"...","state_id":"...","remote_ip":"..."}: the
//     server asked for a federated assertion. Open saml_url, collect the
//     SAMLResponse, and hand it to CompleteSAMLFlow.
//   - JSON object {} (empty): no assertion was asked for and authentication is
//     done. Call CompleteSAMLFlow("") to bring the tunnel up.
//   - "error: <message>": the attempt failed.
func (m *MobileClient) StartSAMLFlow() string {
	challenge, err := m.inner.dialAndAuthenticate(m.ctx)
	if err != nil {
		return "error: " + err.Error()
	}
	if challenge == nil {
		// The server asked for no assertion: authentication is done.
		// Caller must call CompleteSAMLFlow("") to finish.
		return "{}"
	}
	b, err := json.Marshal(map[string]string{
		"saml_url":  challenge.URL,
		"state_id":  challenge.StateID,
		"remote_ip": m.inner.Phase1IP(),
	})
	if err != nil {
		return fmt.Sprintf("error: marshal challenge: %v", err)
	}
	return string(b)
}

// CompleteSAMLFlow brings the tunnel up after StartSAMLFlow. samlToken is the
// base64-encoded SAMLResponse from the identity provider, or "" when
// StartSAMLFlow returned {} and asked for no assertion.
//
// Returns "" on success, or an error description on failure.
func (m *MobileClient) CompleteSAMLFlow(samlToken string) string {
	if err := m.inner.bringUpTunnel(m.ctx, samlToken); err != nil {
		return err.Error()
	}
	return ""
}

// Disconnect begins a graceful teardown of the VPN tunnel.
// Returns "" on success, or an error description on failure.
func (m *MobileClient) Disconnect() string {
	m.cancel()
	if err := m.inner.Disconnect(); err != nil {
		return err.Error()
	}
	return ""
}

// WaitForDisconnect blocks until the tunnel is fully torn down.
// Returns "" for a clean disconnect, or an error description otherwise.
// Call this after Disconnect to ensure resources are freed.
func (m *MobileClient) WaitForDisconnect() string {
	if err := m.inner.WaitForDisconnect(); err != nil {
		return err.Error()
	}
	return ""
}

// Stats returns a JSON string with the current tunnel statistics.
// Keys: "bytes_sent" (int), "bytes_recv" (int), "uptime_sec" (int), "local_ip" (string).
// Returns an error description string if marshalling fails (should not happen).
func (m *MobileClient) Stats() string {
	s := m.inner.Stats()
	b, err := json.Marshal(map[string]any{
		"bytes_sent": s.BytesSent,
		"bytes_recv": s.BytesRecv,
		"uptime_sec": int64(s.Uptime.Seconds()),
		"local_ip":   m.inner.LocalIP(),
	})
	if err != nil {
		return fmt.Sprintf("vpn: marshal stats: %v", err)
	}
	return string(b)
}
