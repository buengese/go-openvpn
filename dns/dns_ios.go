//go:build ios

// iOS DNS stubs — DNS is configured via NEPacketTunnelNetworkSettings;
// the Go layer never calls Apply or Revert directly.
package dns

// Apply is a no-op on iOS — DNS is configured via setTunnelNetworkSettings.
// It returns no backup path because it writes nothing to restore.
func Apply(_ *Config, _ string, _ func(string, ...any)) (Backend, string, error) {
	return BackendNone, "", nil
}

// Revert is a no-op on iOS.
func Revert(_ Backend, _, _ string) error { return nil }
