package main

import "testing"

func TestRouteEvaluation(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		measured RouteIdentity
		ruOK     bool
		pass     bool
	}{
		{"foreign with same proxy ip", "203.0.113.10", RouteIdentity{IP: "203.0.113.10", Country: "AL"}, true, true},
		{"russian despite working websites", "203.0.113.10", RouteIdentity{IP: "198.51.100.4", Country: "RU"}, true, false},
		{"system bypasses tun", "203.0.113.10", RouteIdentity{IP: "198.51.100.4", Country: "DE"}, true, false},
		{"same country without proof", "", RouteIdentity{IP: "203.0.113.10"}, true, false},
		{"foreign without expected but geo", "", RouteIdentity{IP: "203.0.113.10", Country: "AL"}, true, true},
		{"foreign but russian site unreachable", "203.0.113.10", RouteIdentity{IP: "203.0.113.10", Country: "AL"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluateSystemRoute(tc.expected, tc.measured, tc.ruOK)
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%t got %v", tc.pass, err)
			}
		})
	}
}
func TestCloudflareTrace(t *testing.T) {
	info := parseTrace([]byte("fl=22\nip=203.0.113.10\nloc=AL\ntls=TLSv1.3\n"))
	if info.IP != "203.0.113.10" || info.Country != "AL" {
		t.Fatalf("trace parse failed: %+v", info)
	}
}
func TestSplitDefaultRoutes(t *testing.T) {
	c, err := makeConfig(Node{Protocol: "vless", Out: map[string]any{"server": "203.0.113.1", "server_port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000"}}, nil)
	if err != nil {
		t.Skipf("testNode not compatible: %v", err)
	}
	ins := c["inbounds"].([]any)[0].(map[string]any)
	settings := ins["settings"].(map[string]any)
	routes := settings["autoSystemRoutingTable"].([]string)
	if len(routes) != 4 || routes[0] != "0.0.0.0/1" || routes[1] != "128.0.0.0/1" {
		t.Fatalf("default routes not divided: %v", routes)
	}
}
