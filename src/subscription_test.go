package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVLESSReality(t *testing.T) {
	link := "vless://5d2361fe-58f9-4f8d-b6db-39f7da7d8942@edge.example.net:443?security=reality&sni=example.net&pbk=publickey&sid=a1&fp=chrome&flow=xtls-rprx-vision#Server"
	n, e := parseNode(link)
	if e != nil {
		t.Fatal(e)
	}
	if n.Protocol != "vless" || n.Name != "Server" {
		t.Fatalf("node=%+v", n)
	}
	tls := n.Out["tls"].(map[string]any)
	if tls["server_name"] != "example.net" {
		t.Fatal(tls)
	}
	if tls["reality"].(map[string]any)["public_key"] != "publickey" {
		t.Fatal(tls)
	}
}
func TestEncodedSubscriptionAndVMess(t *testing.T) {
	raw := []byte("vless://5d2361fe-58f9-4f8d-b6db-39f7da7d8942@a.example.com:443?security=tls#One\ntrojan://secret@b.example.com:443?sni=b.example.com#Two")
	encoded := base64.StdEncoding.EncodeToString(raw)
	nodes, e := parseSubscription([]byte(encoded))
	if e != nil {
		t.Fatal(e)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d", len(nodes))
	}
	v := map[string]string{"ps": "Test", "add": "example.org", "port": "443", "id": "8ed0b767-a1ef-488a-9fa4-c0f9493110ff", "net": "ws", "path": "/ws", "host": "example.org", "tls": "tls"}
	b, _ := json.Marshal(v)
	vmess := "vmess://" + base64.StdEncoding.EncodeToString(b)
	n, e := parseNode(vmess)
	if e != nil {
		t.Fatal(e)
	}
	if n.Name != "Test" {
		t.Fatal(n.Name)
	}
}
func TestRulesAndJSON(t *testing.T) {
	n, e := parseNode("vless://5d2361fe-58f9-4f8d-b6db-39f7da7d8942@node.example.com:443?security=reality&sni=example.com&pbk=ZmFrZXBr&sid=1a&fp=chrome&type=xhttp&path=%2Fconnect&host=front.example.com&mode=packet-up#Demo")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := makeConfig(n, []string{"1.0.0.0/24"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	for _, part := range []string{`"protocol":"tun"`, `"autoOutboundsInterface":"auto"`, `"geoip:ru"`, `"network":"xhttp"`, `"xhttpSettings"`, `"path":"/connect"`, `"mode":"packet-up"`, `"publicKey":"ZmFrZXBr"`, `"outboundTag":"direct"`, `"1.0.0.0/24"`} {
		if !strings.Contains(string(b), part) {
			t.Errorf("missing %s", part)
		}
	}
}
func TestXhttpImportAndSplit(t *testing.T) {
	raw := "vless://e681c17f-00b1-4ad7-92a9-55f2b53bf3cd@test.example.org:443?type=xhttp&security=tls&sni=edge.example.org&path=%2Fsome%2Fpath&mode=stream-up#My%20XHTTP%20Node"
	nodes, e := parseSubscription([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	if len(nodes) != 1 || nodes[0].Name != "My XHTTP Node" {
		t.Fatal(nodes)
	}
	cfg, e := makeConfig(nodes[0], nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	if !strings.Contains(s, `"network":"xhttp"`) || !strings.Contains(s, `"mode":"stream-up"`) || !strings.Contains(s, `"geoip:ru"`) {
		t.Fatal(s)
	}
}
func TestEncryptedProfileRoundTripForBuild(t *testing.T) {
	a := newApp(t.TempDir())
	nodes, _ := parseSubscription([]byte("trojan://secret@sample.example.com:443"))
	if e := a.saveProfile("https://sub.example.com/private", nodes, 0); e != nil {
		t.Fatal(e)
	}
	b := newApp(a.dir)
	if e := b.readSource(); e != nil {
		t.Fatal(e)
	}
	if b.source != a.source && b.source != "https://sub.example.com/private" {
		t.Fatal(b.source)
	}
	if len(b.nodes) != 1 {
		t.Fatal("nodes lost")
	}
}
func TestLocalAPIToken(t *testing.T) {
	a := newApp(t.TempDir())
	req := httptest.NewRequest("GET", "/api/status", nil)
	rsp := httptest.NewRecorder()
	a.handler().ServeHTTP(rsp, req)
	if rsp.Code != 403 {
		t.Fatal(rsp.Code)
	}
	req.Header.Set("X-Neona-Token", a.token)
	rsp = httptest.NewRecorder()
	a.handler().ServeHTTP(rsp, req)
	if rsp.Code != 200 {
		t.Fatal(rsp.Code)
	}
}
func TestRussianCIDRFileValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ips.txt")
	_ = os.WriteFile(p, []byte("1.2.3.0/24\nBAD\n2.3.0.0/16\n"), 0600)
	s := readRUCIDRs(p)
	if len(s) != 2 {
		t.Fatal(s)
	}
}
func TestRemoteSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("trojan://p@ex.example.com:443")) }))
	defer srv.Close()
	nodes, e := getNodes(srv.URL)
	if e != nil || len(nodes) != 1 {
		t.Fatalf("%v, %+v", e, nodes)
	}
}

// Тесты последовательности preflight и отдельного DNS для адреса VPN-сервера.
func TestProbeConfigDoesNotContainTun(t *testing.T) {
	n, e := parseNode("vless://e681c17f-00b1-4ad7-92a9-55f2b53bf3cd@vpn.example.net:443?type=xhttp&security=tls&path=%2Fup#Probe")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := makeProbeConfig(n, 21001)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(cfg)
	if strings.Contains(string(b), `"protocol":"tun"`) {
		t.Fatal("TUN нельзя включать при проверке сервера")
	}
	if !strings.Contains(string(b), `"protocol":"http"`) || !strings.Contains(string(b), `"network":"xhttp"`) {
		t.Fatal(string(b))
	}
	servers := dnsServers(n)
	b, _ = json.Marshal(servers)
	if !strings.Contains(string(b), `full:vpn.example.net`) {
		t.Fatal("Отдельный DNS для адреса сервера не настроен")
	}
}
func TestNoServerHostBootstrappingForIP(t *testing.T) {
	n, e := parseNode("vless://e681c17f-00b1-4ad7-92a9-55f2b53bf3cd@192.0.2.1:443?type=xhttp&security=tls&path=%2Fup#Probe")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(dnsServers(n))
	if strings.Contains(string(b), "full:192.0.2.1") {
		t.Fatal(string(b))
	}
}
