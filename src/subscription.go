package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Раздел 1. Импорт подписок и одиночных ссылок. Секреты остаются в локальном процессе.
type Node struct {
	Name     string         `json:"name"`
	Protocol string         `json:"protocol"`
	Out      map[string]any `json:"out"`
}

var schemes = []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "anytls://", "tuic://"}

func isShareLink(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, x := range schemes {
		if strings.HasPrefix(s, x) {
			return true
		}
	}
	return false
}
func fromB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, e := enc.DecodeString(s); e == nil && utf8.Valid(b) {
			return b, nil
		}
	}
	return nil, errors.New("не удалось декодировать Base64")
}
func parseSubscription(raw []byte) ([]Node, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if s == "" {
		return nil, errors.New("пустая подписка")
	}
	if strings.HasPrefix(s, "{") {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &obj); err == nil {
			for _, field := range []string{"outbounds", "proxies"} {
				if x, ok := obj[field]; ok {
					var arr []map[string]any
					if json.Unmarshal(x, &arr) == nil {
						var n []Node
						for _, v := range arr {
							typ := asStr(v["type"])
							if typ == "" {
								continue
							}
							switch typ {
							case "direct", "block", "selector", "urltest", "dns":
								continue
							}
							if typ == "shadowsocks" || typ == "vless" || typ == "vmess" || typ == "trojan" || typ == "hysteria2" || typ == "tuic" || typ == "anytls" {
								name := asStr(v["tag"])
								if name == "" {
									name = asStr(v["name"])
								}
								if name == "" {
									name = typ
								}
								v["tag"] = "proxy"
								delete(v, "name")
								n = append(n, Node{Name: name, Protocol: typ, Out: v})
							}
						}
						if len(n) > 0 {
							return n, nil
						}
					}
				}
			}
		}
	}
	if strings.HasPrefix(s, "proxies:") || strings.Contains(s, "\nproxies:") {
		return nil, errors.New("эта подписка возвращает Clash YAML. Экспортируй ссылку в формате V2Ray/Base64 или sing-box JSON — ручной JSON не требуется")
	}
	if !strings.Contains(s, "://") {
		if b, e := fromB64(s); e == nil {
			s = strings.TrimSpace(string(b))
		}
	}
	var nodes []Node
	var errs []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !isShareLink(line) {
			continue
		}
		n, e := parseNode(line)
		if e != nil {
			errs = append(errs, e.Error())
			continue
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("не удалось прочитать узлы: %s", strings.Join(errs, "; "))
		}
		return nil, errors.New("ссылка не содержит поддерживаемых узлов VLESS/VMess/Trojan/SS/Hysteria2/AnyTLS/TUIC")
	}
	return nodes, nil
}
func asStr(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func query(q url.Values, names ...string) string {
	for _, name := range names {
		if v := q.Get(name); v != "" {
			return v
		}
	}
	return ""
}
func numPort(u *url.URL, def int) (int, error) {
	if u.Hostname() == "" {
		return 0, errors.New("отсутствует адрес сервера")
	}
	if u.Port() == "" {
		return def, nil
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil || p < 1 || p > 65535 {
		return 0, errors.New("некорректный порт")
	}
	return p, nil
}
func makeTLS(q url.Values, defaultSNI string, force bool) map[string]any {
	tls := map[string]any{"enabled": true}
	sni := query(q, "sni", "serverName", "peer")
	if sni == "" {
		sni = defaultSNI
	}
	if sni != "" {
		tls["server_name"] = sni
	}
	if query(q, "allowInsecure", "insecure", "skip-cert-verify") == "1" {
		tls["insecure"] = true
	}
	if alpn := query(q, "alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if security := q.Get("security"); security == "reality" {
		tls["reality"] = map[string]any{"enabled": true, "public_key": query(q, "pbk", "publicKey"), "short_id": query(q, "sid", "shortId"), "spider_x": query(q, "spx", "spiderX")}
	}
	if fp := query(q, "fp", "fingerprint"); fp != "" && fp != "none" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	_ = force
	return tls
}
func transport(q url.Values) (map[string]any, error) {
	typ := query(q, "type", "net")
	switch typ {
	case "", "tcp", "raw":
		return nil, nil
	case "ws":
		{
			t := map[string]any{"type": "ws", "path": query(q, "path")}
			if h := query(q, "host"); h != "" {
				t["headers"] = map[string]string{"Host": h}
			}
			return t, nil
		}
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": query(q, "serviceName", "service_name")}, nil
	case "xhttp", "splithttp":
		{
			t := map[string]any{"type": "xhttp", "path": query(q, "path")}
			if h := query(q, "host"); h != "" {
				t["host"] = h
			}
			if mode := query(q, "mode"); mode != "" {
				t["mode"] = mode
			}
			if extra := query(q, "extra"); extra != "" {
				var ex any
				if json.Unmarshal([]byte(extra), &ex) == nil {
					t["extra"] = ex
				}
			}
			return t, nil
		}
	case "httpupgrade":
		{
			t := map[string]any{"type": "httpupgrade", "path": query(q, "path")}
			if h := query(q, "host"); h != "" {
				t["host"] = h
			}
			return t, nil
		}
	case "http", "h2":
		{
			t := map[string]any{"type": "http", "path": query(q, "path")}
			if h := query(q, "host"); h != "" {
				t["host"] = []string{h}
			}
			return t, nil
		}
	default:
		return nil, fmt.Errorf("тип транспорта %s пока не поддерживается", typ)
	}
}
func parseNode(raw string) (Node, error) {
	if strings.HasPrefix(raw, "vmess://") {
		return parseVMess(raw)
	}
	if strings.HasPrefix(raw, "ss://") {
		return parseSS(raw)
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return Node{}, e
	}
	p, e := numPort(u, 443)
	if e != nil {
		return Node{}, e
	}
	q := u.Query()
	protocol := strings.ToLower(u.Scheme)
	if protocol == "hy2" {
		protocol = "hysteria2"
	}
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = protocol + " · " + u.Hostname()
	}
	out := map[string]any{"type": protocol, "tag": "proxy", "server": u.Hostname(), "server_port": p}
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	switch protocol {
	case "vless":
		if user == "" {
			return Node{}, errors.New("VLESS: отсутствует UUID")
		}
		out["uuid"] = user
		if flow := q.Get("flow"); flow != "" {
			out["flow"] = flow
		}
		if enc := q.Get("encryption"); enc != "" {
			out["encryption"] = enc
		}
		sec := q.Get("security")
		if sec == "tls" || sec == "reality" {
			out["tls"] = makeTLS(q, u.Hostname(), true)
		} else if sec != "" && sec != "none" {
			return Node{}, fmt.Errorf("VLESS: неизвестный security %q", sec)
		}
		t, e := transport(q)
		if e != nil {
			return Node{}, e
		}
		if t != nil {
			out["transport"] = t
		}
	case "trojan":
		if user == "" {
			return Node{}, errors.New("Trojan: отсутствует пароль")
		}
		out["password"] = user
		out["tls"] = makeTLS(q, u.Hostname(), true)
		t, e := transport(q)
		if e != nil {
			return Node{}, e
		}
		if t != nil {
			out["transport"] = t
		}
	case "hysteria2":
		if user == "" {
			return Node{}, errors.New("Hysteria2: отсутствует пароль")
		}
		out["password"] = user
		out["tls"] = makeTLS(q, u.Hostname(), true)
		if ob := q.Get("obfs"); ob != "" {
			out["obfs"] = map[string]any{"type": ob, "password": query(q, "obfs-password", "obfsPassword")}
		}
	case "anytls":
		if user == "" {
			return Node{}, errors.New("AnyTLS: отсутствует пароль")
		}
		out["password"] = user
		out["tls"] = makeTLS(q, u.Hostname(), true)
	case "tuic":
		if user == "" {
			return Node{}, errors.New("TUIC: отсутствует UUID")
		}
		out["uuid"] = user
		pass, _ := u.User.Password()
		if pass == "" {
			pass = q.Get("password")
		}
		out["password"] = pass
		out["tls"] = makeTLS(q, u.Hostname(), true)
		if cc := q.Get("congestion_control"); cc != "" {
			out["congestion_control"] = cc
		}
	default:
		return Node{}, fmt.Errorf("неподдерживаемый протокол %s", protocol)
	}
	return Node{Name: name, Protocol: protocol, Out: out}, nil
}
func parseVMess(raw string) (Node, error) {
	b, e := fromB64(strings.TrimPrefix(raw, "vmess://"))
	if e != nil {
		return Node{}, fmt.Errorf("VMess Base64: %w", e)
	}
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		return Node{}, fmt.Errorf("VMess JSON: %w", e)
	}
	name := asStr(v["ps"])
	if name == "" {
		name = "VMess"
	}
	server := asStr(v["add"])
	id := asStr(v["id"])
	port, e := strconv.Atoi(asStr(v["port"]))
	if e != nil || port < 1 || port > 65535 || server == "" || id == "" {
		return Node{}, errors.New("VMess: некорректный адрес, порт или UUID")
	}
	out := map[string]any{"type": "vmess", "tag": "proxy", "server": server, "server_port": port, "uuid": id, "security": "auto"}
	if v["aid"] != nil {
		aid, _ := strconv.Atoi(asStr(v["aid"]))
		out["alter_id"] = aid
	}
	q := url.Values{}
	q.Set("type", asStr(v["net"]))
	q.Set("path", asStr(v["path"]))
	q.Set("host", asStr(v["host"]))
	t, e := transport(q)
	if e != nil {
		return Node{}, e
	}
	if t != nil {
		out["transport"] = t
	}
	if strings.Contains(strings.ToLower(asStr(v["tls"])), "tls") {
		q.Set("sni", asStr(v["sni"]))
		q.Set("alpn", asStr(v["alpn"]))
		out["tls"] = makeTLS(q, server, true)
	}
	return Node{Name: name, Protocol: "vmess", Out: out}, nil
}
func parseSS(raw string) (Node, error) {
	s := strings.TrimPrefix(raw, "ss://")
	frag := ""
	if x := strings.IndexByte(s, '#'); x >= 0 {
		frag = s[x+1:]
		s = s[:x]
	}
	s = strings.SplitN(s, "?", 2)[0]
	if !strings.Contains(s, "@") {
		b, e := fromB64(s)
		if e != nil {
			return Node{}, e
		}
		s = string(b)
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 {
		return Node{}, errors.New("Shadowsocks: неверный формат")
	}
	auth := parts[0]
	if !strings.Contains(auth, ":") {
		b, e := fromB64(auth)
		if e != nil {
			return Node{}, e
		}
		auth = string(b)
	}
	creds := strings.SplitN(auth, ":", 2)
	if len(creds) != 2 {
		return Node{}, errors.New("Shadowsocks: отсутствует метод или пароль")
	}
	method, _ := url.QueryUnescape(creds[0])
	pass, _ := url.QueryUnescape(creds[1])
	host, portS, e := net.SplitHostPort(parts[1])
	if e != nil {
		return Node{}, e
	}
	p, e := strconv.Atoi(portS)
	if e != nil || p < 1 || p > 65535 {
		return Node{}, errors.New("Shadowsocks: неверный порт")
	}
	name, _ := url.QueryUnescape(frag)
	if name == "" {
		name = "Shadowsocks · " + host
	}
	return Node{Name: name, Protocol: "shadowsocks", Out: map[string]any{"type": "shadowsocks", "tag": "proxy", "server": host, "server_port": p, "method": method, "password": pass}}, nil
}
