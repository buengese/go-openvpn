// SPDX-License-Identifier: LGPL-2.1-or-later

package fd

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// TestIfconfigJSONIncludesDNSDomains pins that split-DNS carries all three of
// servers, search domains and route domains: the map is omitempty by
// construction, so dropping one compiles.
func TestIfconfigJSONIncludesDNSDomains(t *testing.T) {
	gotJSON := IfconfigJSON(&routing.PushOptions{}, &dns.Config{
		Servers:       []net.IP{net.ParseIP("10.130.0.2")},
		SearchDomains: []string{"corp.example"},
		RouteDomains:  []string{"internal.company.com", "us-east-2.eks.amazonaws.com"},
	}, 1500)

	var got struct {
		DNS           []string `json:"dns"`
		SearchDomains []string `json:"search_domains"`
		RouteDomains  []string `json:"route_domains"`
	}
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("unmarshal tunnel config: %v", err)
	}

	if want := []string{"10.130.0.2"}; !reflect.DeepEqual(got.DNS, want) {
		t.Errorf("dns = %v, want %v", got.DNS, want)
	}
	if want := []string{"corp.example"}; !reflect.DeepEqual(got.SearchDomains, want) {
		t.Errorf("search_domains = %v, want %v", got.SearchDomains, want)
	}
	if want := []string{"internal.company.com", "us-east-2.eks.amazonaws.com"}; !reflect.DeepEqual(got.RouteDomains, want) {
		t.Errorf("route_domains = %v, want %v", got.RouteDomains, want)
	}
}

// ifconfigRoute mirrors one entry of the "routes" array.
type ifconfigRoute struct {
	Network string `json:"network"`
	Mask    string `json:"mask"`
}

// ifconfigDoc mirrors the documented schema, so a test decoding it fails on a
// renamed key rather than quietly reading a zero value.
type ifconfigDoc struct {
	Local           string          `json:"local"`
	Mask            string          `json:"mask"`
	Peer            string          `json:"peer"`
	Gateway         string          `json:"gateway"`
	MTU             int             `json:"mtu"`
	Routes          []ifconfigRoute `json:"routes"`
	RedirectGateway bool            `json:"redirect_gateway"`
}

// decodeIfconfig parses what IfconfigJSON produced.
func decodeIfconfig(t *testing.T, s string) ifconfigDoc {
	t.Helper()
	var got ifconfigDoc
	if err := json.Unmarshal([]byte(s), &got); err != nil {
		t.Fatalf("unmarshal tunnel config: %v", err)
	}
	return got
}

// TestIfconfigJSONTopology pins the branch a host would silently misconfigure:
// under net30 the pushed gateway is the point-to-point peer and belongs under
// "peer", under subnet it is a real gateway, and the host layer adds a /32
// route for the one and a default next-hop for the other.
func TestIfconfigJSONTopology(t *testing.T) {
	push := func(top routing.Topology, mask net.IPMask) *routing.PushOptions {
		return &routing.PushOptions{
			Topology: top,
			Ifconfig: &routing.Ifconfig{
				Local:   net.ParseIP("172.16.0.6"),
				Mask:    mask,
				Gateway: net.ParseIP("172.16.0.5"),
			},
			Routes: []routing.Route{{
				Network: net.ParseIP("10.0.0.0"),
				Mask:    net.CIDRMask(16, 32),
			}},
			RedirectGateway: true,
		}
	}

	t.Run("net30", func(t *testing.T) {
		got := decodeIfconfig(t, IfconfigJSON(push(routing.TopologyNet30, nil), nil, 1400))
		if got.Peer != "172.16.0.5" {
			t.Errorf("peer = %q, want 172.16.0.5", got.Peer)
		}
		if got.Gateway != "" {
			t.Errorf("gateway = %q, want it absent under net30", got.Gateway)
		}
		if got.Local != "172.16.0.6" || got.MTU != 1400 || !got.RedirectGateway {
			t.Errorf("local/mtu/redirect_gateway = %q/%d/%v, want 172.16.0.6/1400/true",
				got.Local, got.MTU, got.RedirectGateway)
		}
		want := []ifconfigRoute{{Network: "10.0.0.0", Mask: "255.255.0.0"}}
		if !reflect.DeepEqual(got.Routes, want) {
			t.Errorf("routes = %v, want %v", got.Routes, want)
		}
	})

	t.Run("subnet", func(t *testing.T) {
		got := decodeIfconfig(t, IfconfigJSON(push(routing.TopologySubnet, net.CIDRMask(27, 32)), nil, 1400))
		if got.Gateway != "172.16.0.5" {
			t.Errorf("gateway = %q, want 172.16.0.5", got.Gateway)
		}
		if got.Peer != "" {
			t.Errorf("peer = %q, want it absent under subnet", got.Peer)
		}
		if got.Mask != "255.255.255.224" {
			t.Errorf("mask = %q, want 255.255.255.224", got.Mask)
		}
	})
}

// TestIfconfigJSONWithoutIfconfigOrDNS covers the degenerate PUSH_REPLY: the
// builder must still produce parseable JSON rather than panic on a nil
// Ifconfig.
func TestIfconfigJSONWithoutIfconfigOrDNS(t *testing.T) {
	got := IfconfigJSON(&routing.PushOptions{}, nil, 1500)

	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("unmarshal tunnel config: %v", err)
	}
	for _, absent := range []string{"local", "mask", "peer", "gateway", "dns", "routes"} {
		if _, ok := m[absent]; ok {
			t.Errorf("key %q present with nothing pushed: %s", absent, got)
		}
	}
	if m["mtu"] != float64(1500) {
		t.Errorf("mtu = %v, want 1500", m["mtu"])
	}
	if m["redirect_gateway"] != false {
		t.Errorf("redirect_gateway = %v, want false", m["redirect_gateway"])
	}
}
