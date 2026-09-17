//go:build android || darwin || mobileapi

package vpn

import (
	"context"
	"strings"
	"testing"
)

// mobileUserPassProfile is a username/password profile: no client certificate,
// so AuthFlow reads it as FlowUserPass and the attempt needs credentials. The
// CA is the package's real test certificate, because Preflight refuses an
// unparseable one before it gets as far as asking about credentials.
func mobileUserPassProfile(t *testing.T) string {
	t.Helper()
	return "client\nremote vpn.example.com 443\nproto tcp-client\nauth-user-pass\n" +
		"<ca>\n" + string(testCAPEM(t)) + "</ca>\n"
}

// TestSetCredentialsIsWhatMakesAUserPassProfileConnectable is the gap this
// method closes: gomobile cannot bind a function value, so the CredentialsFn
// the Go API uses does not cross the boundary, and a profile asking for a
// password would otherwise be unreachable from Android and iOS.
func TestSetCredentialsIsWhatMakesAUserPassProfileConnectable(t *testing.T) {
	// Two clients rather than one, because Preflight is beginAttempt and
	// beginAttempt is idempotent: it caches the answer to the first call and
	// returns it to every later one. Asking the same client before and after
	// would only ever report the "before".
	t.Run("without credentials the attempt is refused before it dials", func(t *testing.T) {
		mc := NewMobileClient(mobileUserPassProfile(t), nil)
		if mc.inner.CredentialsFn != nil {
			t.Fatal("a fresh MobileClient already has a credential callback")
		}
		err := mc.inner.Preflight()
		if err == nil {
			t.Fatal("a user-pass profile with no credentials passed the preflight")
		}
		if !strings.Contains(err.Error(), "username and password") {
			t.Errorf("refusal was %q, want it to name what is missing", err)
		}
	})

	t.Run("with credentials it is connectable", func(t *testing.T) {
		mc := NewMobileClient(mobileUserPassProfile(t), nil)
		if errStr := mc.SetCredentials("alice", "hunter2"); errStr != "" {
			t.Fatalf("SetCredentials: %s", errStr)
		}
		if mc.inner.CredentialsFn == nil {
			t.Fatal("SetCredentials installed no credential callback")
		}
		creds, err := mc.inner.CredentialsFn(context.Background())
		if err != nil {
			t.Fatalf("credential callback: %v", err)
		}
		if creds.Username != "alice" || creds.Password != "hunter2" {
			t.Errorf("callback returned %q/%q, want alice/hunter2", creds.Username, creds.Password)
		}
		if err := mc.inner.Preflight(); err != nil {
			t.Errorf("a user-pass profile with credentials still fails the preflight: %v", err)
		}
	})
}

// TestSetCredentialsAnswersEveryAttempt pins the reason this is a stored value
// and not a one-shot: the callback is asked once per attempt, and a reconnect
// is another attempt.
func TestSetCredentialsAnswersEveryAttempt(t *testing.T) {
	mc := NewMobileClient(mobileUserPassProfile(t), nil)
	if errStr := mc.SetCredentials("alice", "hunter2"); errStr != "" {
		t.Fatalf("SetCredentials: %s", errStr)
	}
	for i := range 3 {
		creds, err := mc.inner.CredentialsFn(context.Background())
		if err != nil || creds.Password != "hunter2" {
			t.Fatalf("attempt %d: got %q/%v, want the stored password", i, creds.Password, err)
		}
	}
}

// TestSetCredentialsReplacesWhatItWasGiven covers the retry a host makes after
// a rejection: calling it again must change the answer without rebuilding the
// client.
func TestSetCredentialsReplacesWhatItWasGiven(t *testing.T) {
	mc := NewMobileClient(mobileUserPassProfile(t), nil)
	mc.SetCredentials("alice", "wrong")   //nolint:errcheck
	mc.SetCredentials("alice", "hunter2") //nolint:errcheck

	creds, err := mc.inner.CredentialsFn(context.Background())
	if err != nil {
		t.Fatalf("credential callback: %v", err)
	}
	if creds.Password != "hunter2" {
		t.Errorf("password = %q, want the second one", creds.Password)
	}
}

// TestSetCredentialsRefusesAnEmptyHalf keeps an unusable credential out of the
// key-method-2 packet. Presented to a server it comes back AUTH_FAILED, which
// tells the host nothing about which half was missing.
func TestSetCredentialsRefusesAnEmptyHalf(t *testing.T) {
	for _, tc := range []struct{ name, user, pass string }{
		{"no username", "", "hunter2"},
		{"no password", "alice", ""},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := NewMobileClient(mobileUserPassProfile(t), nil)
			errStr := mc.SetCredentials(tc.user, tc.pass)
			if errStr == "" {
				t.Fatal("an empty credential was accepted")
			}
			if mc.inner.CredentialsFn != nil {
				t.Error("a refused credential still installed a callback")
			}
			if strings.Contains(errStr, tc.pass) && tc.pass != "" {
				t.Errorf("the error text disclosed the password: %q", errStr)
			}
		})
	}
}

// TestDisconnectDropsTheCredentials pins that the password does not outlive the
// connection it was given for. The host keeps its own copy; this one has no
// further use once the session is over.
func TestDisconnectDropsTheCredentials(t *testing.T) {
	mc := NewMobileClient(mobileUserPassProfile(t), nil)
	if errStr := mc.SetCredentials("alice", "hunter2"); errStr != "" {
		t.Fatalf("SetCredentials: %s", errStr)
	}
	mc.Disconnect() //nolint:errcheck

	mc.mu.Lock()
	held := mc.creds
	mc.mu.Unlock()
	if held.Username != "" || held.Password != "" {
		t.Errorf("the client still holds %q/%q after Disconnect", held.Username, held.Password)
	}
	// And the callback now refuses rather than presenting an empty pair.
	if _, err := mc.inner.CredentialsFn(context.Background()); err == nil {
		t.Error("the callback answered after Disconnect dropped the credentials")
	}
}

// TestACertificateProfileIsUntouched is the other half: installing a credential
// path must not change a profile that does not use one.
func TestACertificateProfileIsUntouched(t *testing.T) {
	certProfile := "client\nremote vpn.example.com 443\nproto tcp-client\n" +
		"<ca>\n" + string(testCAPEM(t)) + "</ca>\n" +
		"<cert>\n-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n</cert>\n" +
		"<key>\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n</key>\n"

	mc := NewMobileClient(certProfile, nil)
	if mc.inner.CredentialsFn != nil {
		t.Error("a certificate profile was given a credential callback")
	}
	if err := mc.inner.Preflight(); err != nil {
		t.Errorf("a certificate profile needs no credentials but failed the preflight: %v", err)
	}
}
