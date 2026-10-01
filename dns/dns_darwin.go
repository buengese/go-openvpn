//go:build darwin && !ios

// macOS DNS configuration for the CLI (Path A — native utun).
//
// DNS is injected into SCDynamicStore via `scutil --set` scoped to the VPN's own
// service key (State:/Network/Service/<ifName>/DNS): mDNSResponder picks the
// entry up immediately without polluting the Wi-Fi or Ethernet service, and it
// disappears when the interface goes down. The fallback is a /etc/resolv.conf
// overwrite, rarely needed since scutil works as root on all modern versions.
//
// On Path B (GUI / NEPacketTunnelProvider) the OS applies DNS via
// setTunnelNetworkSettings; these functions are never called.
package dns

import (
	"fmt"
	"os/exec"
	"strings"
)

// Apply injects VPN DNS via SCDynamicStore (scutil) scoped to ifName.
// Falls back to /etc/resolv.conf if scutil fails.
// It returns the backup path to hand to Revert, which is empty unless the
// resolv.conf fallback was actually taken.
//
// logf, if non-nil, is told when the resolv.conf fallback is taken.
func Apply(cfg *Config, ifName string, logf func(string, ...any)) (Backend, string, error) {
	if cfg == nil || len(cfg.Servers) == 0 {
		return BackendNone, "", nil
	}

	if err := applyScutil(cfg, ifName); err == nil {
		return BackendResolved, "", nil
	} else if logf != nil {
		logf("dns: scutil failed (%v), falling back to /etc/resolv.conf", err)
	}

	// Fallback: overwrite /etc/resolv.conf.
	backupPath, err := newResolvConfBackup()
	if err != nil {
		return BackendNone, "", err
	}
	return BackendResolvConf, backupPath, ApplyResolvConf(cfg)
}

// Revert removes DNS settings applied by Apply.
func Revert(backend Backend, ifName, backupPath string) error {
	switch backend {
	case BackendResolved:
		return revertScutil(ifName)
	case BackendResolvConf:
		return RestoreResolvConf(backupPath)
	default:
		return nil
	}
}

// applyScutil injects a DNS entry into SCDynamicStore for the given interface.
// mDNSResponder picks this up immediately; the entry is scoped to the VPN
// service key and does not affect Wi-Fi or Ethernet.
func applyScutil(cfg *Config, ifName string) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add ServerAddresses *")
	for _, srv := range cfg.Servers {
		script.WriteString(" ")
		script.WriteString(srv.String())
	}
	script.WriteString("\n")
	if len(cfg.SearchDomains) > 0 {
		script.WriteString("d.add SearchDomains *")
		for _, dom := range cfg.SearchDomains {
			script.WriteString(" ")
			script.WriteString(dom)
		}
		script.WriteString("\n")
	}
	// SupplementalMatchDomains with an empty string makes this a split-DNS
	// entry: mDNSResponder uses this resolver only for VPN-pushed domains,
	// or for all of them when no match domains are given and the tunnel is
	// the default route.
	script.WriteString("d.add SupplementalMatchDomains *\n")
	script.WriteString(fmt.Sprintf("set State:/Network/Service/%s/DNS\n", ifName))

	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil DNS inject: %w — %s", err, string(out))
	}
	return nil
}

// revertScutil removes the SCDynamicStore DNS entry for ifName.
func revertScutil(ifName string) error {
	script := fmt.Sprintf("remove State:/Network/Service/%s/DNS\n", ifName)
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil DNS remove: %w — %s", err, string(out))
	}
	return nil
}
