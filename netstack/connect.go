// SPDX-License-Identifier: LGPL-2.1-or-later

// The front door: Connect returns something you dial through. The wrapping runs
// this way round — netstack imports the root vpn package and never the reverse —
// so that gVisor reaches a binary only when something imports this package.

package netstack

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// Options configures a Connect. The zero value is valid and is what a
// measurement consumer wanting default behaviour passes.
type Options struct {
	// PreflightMode selects what the capability preflight does with a fatal
	// gap. The zero value ends the attempt at StageParse before a socket is
	// opened; diag.PreflightAdvisory records the same gaps and proceeds anyway,
	// so the attempt fails where it really fails.
	PreflightMode diag.PreflightMode

	// EventFn, when set, receives every lifecycle event: state changes, log
	// lines and periodic stats. It is called from internal goroutines and
	// must not block.
	EventFn vpn.EventFn

	// DeviceName, when non-empty, names the tunnel device in logs and in the
	// session report. Left empty, each device is numbered.
	DeviceName string

	// CredentialsFn supplies the username and password for a profile that
	// requires them, once per attempt and before the key-method-2 packet is
	// sent; it may block on a UI or a keychain. A profile carrying
	// auth-user-pass without it ends at StageParse with diag.ClassConfig.
	CredentialsFn func(ctx context.Context) (vpn.Credentials, error)

	// DataV2 selects whether the IV_PROTO advertisement claims
	// IV_PROTO_DATA_V2. The zero value claims it: P_DATA_V2 is the preferred
	// data-channel format. vpn.WithholdDataV2 is not a fallback — the format
	// itself is still selected from what the server pushes.
	DataV2 vpn.DataV2Advertisement

	// MaxReconnects caps how many attempts Tunnel.Reconnect makes. The zero
	// value is unlimited: right for a client holding a tunnel open, wrong for
	// a consumer that must not block forever. Reconnect retries only failures
	// a second attempt could resolve, so a cap bounds waiting, not trying.
	MaxReconnects int
}

// Tunnel is a live tunnel you can dial through. It embeds *Net, so every dialer
// method is available directly on it, and adds the session report and teardown.
type Tunnel struct {
	*Net

	client *vpn.Client

	closeOnce sync.Once
	closeErr  error
}

// Connect brings up a tunnel over a userspace network stack and returns
// something you can dial through. It needs no privilege and changes nothing
// about the host, so many of these run concurrently in one process without
// colliding over an interface name, a route table or a resolver.
//
// On failure it returns a nil Tunnel; use ConnectWithReport when the reason an
// attempt failed is itself the result you are after.
func Connect(ctx context.Context, prof *profile.Profile, opts Options) (*Tunnel, error) {
	t, _, err := ConnectWithReport(ctx, prof, opts)
	return t, err
}

// ConnectWithReport is Connect that also returns the session report, on success
// and on failure alike. A failed attempt still produces a populated report —
// which stage it reached, what class of error ended it, what the server
// advertised on the way — so a nil Tunnel never means a lost report. The
// returned report is never nil, even when the profile is unusable.
func ConnectWithReport(ctx context.Context, prof *profile.Profile, opts Options) (*Tunnel, *diag.SessionReport, error) {
	if prof == nil {
		return nil, &diag.SessionReport{}, errors.New("netstack: nil profile")
	}

	c := vpn.New(prof)
	c.Device = &Backend{Name: opts.DeviceName}
	c.PreflightMode = opts.PreflightMode
	c.MaxReconnects = opts.MaxReconnects
	if opts.EventFn != nil {
		c.EventFn = opts.EventFn
	}
	if opts.CredentialsFn != nil {
		c.CredentialsFn = opts.CredentialsFn
	}
	c.DataV2 = opts.DataV2

	if err := c.Connect(ctx); err != nil {
		// Tear down whatever came up before the failure, then hand back the
		// report that explains it.
		c.Disconnect()        //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
		return nil, reportOf(c), err
	}

	n, err := networkOf(c)
	if err != nil {
		c.Disconnect()        //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
		return nil, reportOf(c), err
	}

	return &Tunnel{Net: n, client: c}, reportOf(c), nil
}

// networkOf extracts the dialer surface from a connected client. The device is
// ours by construction — Connect set the backend — but the core hands back a
// device.Device, so a failed assertion means something replaced the backend
// underneath us.
func networkOf(c *vpn.Client) (*Net, error) {
	d, ok := c.TunnelDevice().(*Device)
	if !ok {
		return nil, fmt.Errorf("netstack: tunnel came up on a %T, not a netstack device", c.TunnelDevice())
	}
	return d.Network(), nil
}

// reportOf returns a non-nil report for a client in any state.
func reportOf(c *vpn.Client) *diag.SessionReport {
	if rep := c.Report(); rep != nil {
		return rep
	}
	return &diag.SessionReport{}
}

// Report returns the session report for this tunnel: every stage it passed
// through, what was negotiated, and the data-channel counters as they stand. It
// is safe to call at any time and reflects the tunnel as it is now.
func (t *Tunnel) Report() *diag.SessionReport {
	return reportOf(t.client)
}

// Stats returns the traffic counters for this tunnel.
func (t *Tunnel) Stats() vpn.Stats { return t.client.Stats() }

// Lifetime describes how long the tunnel has been up and what has happened to
// it, for a caller holding a tunnel open rather than measuring a handshake.
//
// Report answers what a connection attempt did and settles once the attempt is
// over; this answers what the connection has been doing since.
type Lifetime struct {
	// Since is when the current tunnel was established, or the zero time if
	// none is up.
	Since time.Time
	// Rekeys is how many key renegotiations have completed, in either
	// direction — a rekey the server started counts the same as one this
	// client started.
	Rekeys uint64
	// Reconnects is how many times the tunnel has been re-established under
	// the same consumer. It counts successes; a reconnect sequence's failed
	// attempts are in Attempts, each with its own report.
	Reconnects int
	// LastError is the most recent transient failure the tunnel recovered
	// from, or nil. A failure that ended the session is the session's outcome
	// and is in the report instead; without this field, a tunnel whose
	// renegotiations have been failing for an hour reads like a healthy one.
	LastError error
}

// Lifetime returns what has happened to this tunnel since it came up. Safe to
// call at any time and from any goroutine, including while a soak is holding
// the tunnel open.
func (t *Tunnel) Lifetime() Lifetime {
	return Lifetime{
		Since:      t.client.ConnectedAt(),
		Rekeys:     reportOf(t.client).Counters.Rekeys,
		Reconnects: t.client.Reconnects(),
		LastError:  t.client.LastTransientError(),
	}
}

// Reconnect re-establishes the tunnel after the link underneath it failed, and
// repoints this Tunnel at the stack that comes back.
//
// A netstack tunnel's addresses come from the PUSH_REPLY, so a reconnect opens
// a new device with a new gVisor stack and every connection through the old one
// is gone. A caller that kept its own *Net has to take Net again, which is also
// why this is not safe to call concurrently with the dialer methods.
// Options.MaxReconnects bounds the attempts and Attempts explains them; on
// failure the tunnel is down, Net is the closed stack of the session that
// ended, and Close is still how to finish with it.
func (t *Tunnel) Reconnect(ctx context.Context) error {
	if err := t.client.Reconnect(ctx); err != nil {
		return err
	}
	n, err := networkOf(t.client)
	if err != nil {
		return err
	}
	t.Net = n
	return nil
}

// Attempts returns one Attempt per attempt of the current or most recent
// Reconnect, in order, each carrying its own session report. Report answers for
// the most recent attempt only; the reason attempt 3 failed is in attempt 3's
// report and nowhere else.
func (t *Tunnel) Attempts() []vpn.Attempt { return t.client.Attempts() }

// Close tears the tunnel down and waits for it to finish. It is idempotent, and
// because a netstack tunnel installed no host state there is nothing left
// behind for anyone else to clean up.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		if err := t.client.Disconnect(); err != nil {
			t.closeErr = err
		}
		if err := t.client.WaitForDisconnect(); err != nil && t.closeErr == nil {
			t.closeErr = err
		}
	})
	return t.closeErr
}
