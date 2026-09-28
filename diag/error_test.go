package diag_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/diag"
)

// TestErrorsAsThroughWrapping pins the contract that makes the taxonomy usable:
// the typed error must survive arbitrary fmt.Errorf("%w") nesting, so that no
// call site ever has to match on message text.
func TestErrorsAsThroughWrapping(t *testing.T) {
	cause := errors.New("connection reset by peer")
	base := diag.Wrap(diag.ClassCrypto, diag.StageKeys, cause, "key derivation mismatch")

	// Four levels of wrapping: errors.As has to reach through all of them.
	err := error(base)
	for i := range 4 {
		err = fmt.Errorf("layer %d: %w", i, err)
	}

	var derr *diag.Error
	if !errors.As(err, &derr) {
		t.Fatalf("errors.As did not recover *diag.Error from %v", err)
	}
	if derr != base {
		t.Fatalf("errors.As recovered %#v, want the original *diag.Error", derr)
	}
	if derr.Class != diag.ClassCrypto || derr.Stage != diag.StageKeys {
		t.Errorf("recovered class/stage = %s/%s, want crypto/keys", derr.Class, derr.Stage)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is did not reach the wrapped cause")
	}
	if got := diag.AsError(err); got != base {
		t.Errorf("AsError = %#v, want the original *diag.Error", got)
	}
	if got := diag.AsError(cause); got != nil {
		t.Errorf("AsError on an untyped error = %#v, want nil", got)
	}
}

func TestErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		err  *diag.Error
		want string
	}{
		{
			name: "full",
			err: &diag.Error{
				Class:   diag.ClassUnsupported,
				Stage:   diag.StageParse,
				Feature: "tls-crypt",
				Detail:  "control channel encryption unimplemented",
				Err:     errors.New("boom"),
			},
			want: "parse: unsupported (tls-crypt): control channel encryption unimplemented: boom",
		},
		{
			name: "bare",
			err:  &diag.Error{Class: diag.ClassNetwork, Stage: diag.StageDial},
			want: "dial: network",
		},
		{
			// A nil cause, which is the case Wrap's doc promises still
			// yields a usable *Error rather than a nil one.
			name: "detail only",
			err:  diag.Wrap(diag.ClassAuth, diag.StageAuth, nil, "AUTH_FAILED"),
			want: "auth: auth: AUTH_FAILED",
		},
		{
			name: "unsupported helper",
			err:  diag.Unsupported(diag.StageKeys, "prf", "classic PRF unimplemented"),
			want: "keys: unsupported (prf): classic PRF unimplemented",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("cause")
	e := diag.Wrap(diag.ClassTLS, diag.StageTLS, cause, "handshake failed")
	if e.Unwrap() != cause {
		t.Errorf("Unwrap = %v, want %v", e.Unwrap(), cause)
	}
	causeless := diag.Wrap(diag.ClassTLS, diag.StageTLS, nil, "no cause")
	if causeless == nil {
		t.Fatal("Wrap with a nil cause returned nil; its doc says it never does")
	}
	if got := causeless.Unwrap(); got != nil {
		t.Errorf("Unwrap of a causeless Error = %v, want nil", got)
	}
	var nilErr *diag.Error
	if got := nilErr.Error(); got != "<nil>" {
		t.Errorf("nil receiver Error() = %q, want %q", got, "<nil>")
	}
	if got := nilErr.Unwrap(); got != nil {
		t.Errorf("nil receiver Unwrap() = %v, want nil", got)
	}
}

func TestErrorChain(t *testing.T) {
	if got := diag.ErrorChain(nil); got != nil {
		t.Errorf("ErrorChain(nil) = %v, want nil", got)
	}

	cause := errors.New("i/o timeout")
	base := diag.Wrap(diag.ClassNetwork, diag.StageDial, cause, "dial failed")
	err := fmt.Errorf("vpn: connect: %w", base)

	chain := diag.ErrorChain(err)
	if len(chain) != 3 {
		t.Fatalf("ErrorChain length = %d (%q), want 3", len(chain), chain)
	}
	if !strings.HasPrefix(chain[0], "vpn: connect: ") {
		t.Errorf("chain[0] = %q, want the outermost message", chain[0])
	}
	if chain[len(chain)-1] != "i/o timeout" {
		t.Errorf("chain[last] = %q, want the innermost cause", chain[len(chain)-1])
	}
}

func TestErrorChainJoined(t *testing.T) {
	a := errors.New("first")
	b := errors.New("second")
	chain := diag.ErrorChain(fmt.Errorf("both: %w", errors.Join(a, b)))
	joined := strings.Join(chain, "|")
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ErrorChain over errors.Join lost %q: %q", want, joined)
		}
	}
}
