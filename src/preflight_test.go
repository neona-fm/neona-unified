package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeUsesNoProxyDependentDNS(t *testing.T) {
	node, err := parseNode("vless://e681c17f-00b1-4ad7-92a9-55f2b53bf3cd@vpn.example.net:443?type=xhttp&security=tls&sni=vpn.example.net&path=%2Fup#Probe")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := makeProbeConfig(node, 25252)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `"protocol":"tun"`) || strings.Contains(s, `"dns":`) || strings.Contains(s, "dns-query") {
		t.Fatal("probe uses TUN or DNS through untested proxy:", s)
	}
	if !strings.Contains(s, `"tag":"direct"`) || !strings.Contains(s, `"loglevel":"info"`) || !strings.Contains(s, `"network":"xhttp"`) {
		t.Fatal("required preflight settings missing:", s)
	}
}
func TestSafeLogKeepsErrorAndRedactsLinks(t *testing.T) {
	s := safeLog(`Get "https://api.ipify.org/": proxyconnect tcp: context deadline exceeded; vless://abcd@host.example:443`)
	if !strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "api.ipify.org") || strings.Contains(s, "vless://") {
		t.Fatal(s)
	}
}
