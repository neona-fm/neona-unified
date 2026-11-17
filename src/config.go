package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Раздел 2. Xray: единый Windows TUN + VLESS/XHTTP + split DNS + RU direct.
// Реальные пароли и UUID остаются только в DPAPI и кратковременном active.json.
var ruDomains = []string{"regexp:(?i)\\.(ru|su|xn--p1ai)$"}

func readRUCIDRs(file string) []string {
	f, e := os.Open(file)
	if e != nil {
		return nil
	}
	defer f.Close()
	out := []string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		p, e := netip.ParsePrefix(v)
		if e != nil || !p.Addr().Is4() {
			continue
		}
		out = append(out, p.String())
		if len(out) >= 12000 {
			break
		}
	}
	return out
}
func xrayOutbound(node Node) (map[string]any, error) {
	out := node.Out
	if out == nil {
		return nil, errors.New("пустая конфигурация сервера")
	}
	server := asStr(out["server"])
	if server == "" {
		return nil, errors.New("в сервере нет адреса")
	}
	port := out["server_port"]
	if port == nil {
		return nil, errors.New("в сервере нет порта")
	}
	security := "none"
	stream := map[string]any{"network": "tcp", "security": "none"}
	if tr, ok := out["transport"].(map[string]any); ok {
		typ := asStr(tr["type"])
		switch typ {
		case "tcp", "raw", "":
			stream["network"] = "tcp"
		case "xhttp", "splithttp":
			stream["network"] = "xhttp"
			settings := map[string]any{}
			for _, k := range []string{"path", "host", "mode"} {
				if v := asStr(tr[k]); v != "" {
					settings[k] = v
				}
			}
			if v := tr["headers"]; v != nil {
				settings["headers"] = v
			}
			if v := tr["extra"]; v != nil {
				settings["extra"] = v
			}
			stream["xhttpSettings"] = settings
		case "ws":
			stream["network"] = "ws"
			settings := map[string]any{"path": asStr(tr["path"])}
			if h := tr["headers"]; h != nil {
				settings["headers"] = h
			}
			stream["wsSettings"] = settings
		case "grpc":
			stream["network"] = "grpc"
			stream["grpcSettings"] = map[string]any{"serviceName": asStr(tr["service_name"])}
		case "httpupgrade":
			stream["network"] = "httpupgrade"
			stream["httpupgradeSettings"] = map[string]any{"path": asStr(tr["path"]), "host": asStr(tr["host"])}
		default:
			return nil, fmt.Errorf("Xray: транспорт %s пока не преобразуется", typ)
		}
	}
	if tls, ok := out["tls"].(map[string]any); ok {
		security = "tls"
		stream["security"] = "tls"
		tlsSettings := map[string]any{}
		if v := asStr(tls["server_name"]); v != "" {
			tlsSettings["serverName"] = v
		}
		if v := tls["alpn"]; v != nil {
			tlsSettings["alpn"] = v
		}
		if tls["insecure"] == true {
			tlsSettings["allowInsecure"] = true
		}
		if utls, ok := tls["utls"].(map[string]any); ok {
			if fp := asStr(utls["fingerprint"]); fp != "" {
				tlsSettings["fingerprint"] = fp
			}
		}
		if reality, ok := tls["reality"].(map[string]any); ok && reality["enabled"] == true {
			security = "reality"
			stream["security"] = "reality"
			r := map[string]any{"serverName": tlsSettings["serverName"], "publicKey": asStr(reality["public_key"]), "shortId": asStr(reality["short_id"])}
			if f := tlsSettings["fingerprint"]; f != nil {
				r["fingerprint"] = f
			} else {
				r["fingerprint"] = "chrome"
			}
			if v := asStr(reality["spider_x"]); v != "" {
				r["spiderX"] = v
			}
			stream["realitySettings"] = r
			delete(stream, "tlsSettings")
		} else {
			stream["tlsSettings"] = tlsSettings
		}
	}
	_ = security
	switch node.Protocol {
	case "vless":
		id := asStr(out["uuid"])
		if id == "" {
			return nil, errors.New("VLESS: пустой UUID")
		}
		user := map[string]any{"id": id, "encryption": "none"}
		if flow := asStr(out["flow"]); flow != "" {
			user["flow"] = flow
		}
		if enc := asStr(out["encryption"]); enc != "" {
			user["encryption"] = enc
		}
		return map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": server, "port": port, "users": []any{user}}}}, "streamSettings": stream}, nil
	case "trojan":
		pass := asStr(out["password"])
		if pass == "" {
			return nil, errors.New("Trojan: нет пароля")
		}
		return map[string]any{"tag": "proxy", "protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": server, "port": port, "password": pass}}}, "streamSettings": stream}, nil
	case "vmess":
		id := asStr(out["uuid"])
		if id == "" {
			return nil, errors.New("VMess: пустой UUID")
		}
		user := map[string]any{"id": id, "security": "auto"}
		if alter := out["alter_id"]; alter != nil {
			user["alterId"] = alter
		}
		return map[string]any{"tag": "proxy", "protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": server, "port": port, "users": []any{user}}}}, "streamSettings": stream}, nil
	default:
		return nil, fmt.Errorf("этот релиз пока поддерживает VLESS, Trojan и VMess; у выбранного сервера %s", node.Protocol)
	}
}

// Отдельный DNS для самого VPN-сервера: предотвращает зависимость его адреса
// от DoH, который ещё только должен заработать через этот сервер.
func dnsServers(node Node) []any {
	servers := []any{map[string]any{"address": "77.88.8.8", "domains": ruDomains, "skipFallback": true}}
	server := strings.TrimSpace(asStr(node.Out["server"]))
	if server != "" && net.ParseIP(server) == nil {
		servers = append(servers, map[string]any{
			"address": "77.88.8.8", "domains": []string{"full:" + server}, "skipFallback": true,
		})
	}
	return append(servers, "https://1.1.1.1/dns-query")
}
func makeConfig(node Node, ruCIDRs []string) (map[string]any, error) {
	proxy, e := xrayOutbound(node)
	if e != nil {
		return nil, e
	}
	rules := []any{
		map[string]any{"type": "field", "inboundTag": []string{"tun-in"}, "port": "53", "outboundTag": "dns-out"},
		map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "domain": ruDomains, "outboundTag": "direct"},
		map[string]any{"type": "field", "ip": []string{"77.88.8.8", "geoip:ru"}, "outboundTag": "direct"},
	}
	if len(ruCIDRs) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": ruCIDRs, "outboundTag": "direct"})
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"dns": map[string]any{
			"servers": dnsServers(node), "queryStrategy": "UseIPv4", "disableFallbackIfMatch": true,
		},
		"inbounds": []any{map[string]any{"tag": "tun-in", "protocol": "tun",
			"settings": map[string]any{
				"name": "NeonaSplitVPN", "desc": "Neona Split VPN", "mtu": 1400,
				"gateway":                []string{"172.19.83.1/30", "fd00:198:83::1/126"},
				"dns":                    []string{"1.1.1.1"},
				"autoSystemRoutingTable": []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
				"autoOutboundsInterface": "auto",
				"autoSystemWfpBlockLeak": []string{"dns", "misconfigtun"},
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		}},
		"outbounds": []any{proxy, map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "dns-out", "protocol": "dns"}},
		"routing":   map[string]any{"domainStrategy": "IPIfNonMatch", "domainMatcher": "hybrid", "rules": rules},
	}
	return cfg, nil
}
func writeConfig(node Node, cidrPath, configPath string) error {
	cfg, e := makeConfig(node, readRUCIDRs(cidrPath))
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(cfg, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(configPath), 0700); e != nil {
		return e
	}
	tmp := configPath + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	if e = os.Rename(tmp, configPath); e != nil {
		_ = os.Remove(configPath)
		return os.Rename(tmp, configPath)
	}
	return nil
}
