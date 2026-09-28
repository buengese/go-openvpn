// SPDX-License-Identifier: LGPL-2.1-or-later

package fd

import (
	"encoding/json"
	"net"

	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/routing"
)

// IfconfigJSON serialises the TUN configuration as a JSON string for the host's
// establish callback. The Android layer uses it to configure
// VpnService.Builder before calling establish(); the iOS and macOS layers use
// it to build NEPacketTunnelNetworkSettings before calling
// setTunnelNetworkSettings. Nothing in the client core reads it back.
//
// The schema is consumed by the Kotlin and Swift layers as it stands. Adding a
// key is safe; renaming or removing one is not.
//
// JSON schema:
//
//	{
//	  "local":   "172.16.0.6",
//	  "mask":    "255.255.255.224",   // subnet topology
//	  "peer":    "172.16.0.5",        // net30 topology (omitted when mask present)
//	  "gateway": "172.16.0.1",
//	  "mtu":     1500,
//	  "dns":     ["10.0.0.2"],
//	  "search_domains": ["corp.example"],
//	  "route_domains": ["internal.example"],
//	  "routes":  [{"network":"10.0.0.0","mask":"255.255.0.0"}],
//	  "redirect_gateway": false
//	}
func IfconfigJSON(push *routing.PushOptions, dnsOpts *dns.Config, mtu int) string {
	type routeJSON struct {
		Network string `json:"network"`
		Mask    string `json:"mask"`
	}
	m := map[string]any{
		"mtu":              mtu,
		"redirect_gateway": push.RedirectGateway,
	}
	if push.Ifconfig != nil {
		m["local"] = push.Ifconfig.Local.String()
		if push.Ifconfig.Mask != nil {
			m["mask"] = net.IP(push.Ifconfig.Mask).String()
		}
		if push.Ifconfig.Gateway != nil {
			if push.Topology == routing.TopologyNet30 {
				// net30: Gateway is the P2P peer; Kotlin reads "peer" to add a /32 route.
				m["peer"] = push.Ifconfig.Gateway.String()
			} else {
				m["gateway"] = push.Ifconfig.Gateway.String()
			}
		}
	}
	var routes []routeJSON
	for _, r := range push.Routes {
		routes = append(routes, routeJSON{
			Network: r.Network.String(),
			Mask:    net.IP(r.Mask).String(),
		})
	}
	if routes != nil {
		m["routes"] = routes
	}
	if dnsOpts != nil {
		var servers []string
		for _, ip := range dnsOpts.Servers {
			servers = append(servers, ip.String())
		}
		if servers != nil {
			m["dns"] = servers
		}
		if len(dnsOpts.SearchDomains) > 0 {
			m["search_domains"] = dnsOpts.SearchDomains
		}
		if len(dnsOpts.RouteDomains) > 0 {
			m["route_domains"] = dnsOpts.RouteDomains
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}
