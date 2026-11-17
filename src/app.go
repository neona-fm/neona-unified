package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Раздел 4. Управление соединением и защитный таймер отката.
type App struct {
	mu              sync.Mutex
	dir             string
	token           string
	source          string
	nodes           []Node
	selected        int
	cmd             *exec.Cmd
	running         bool
	confirmed       bool
	proxyExpectedIP string
	timer           *time.Timer
	status          string
	note            string
	logFile         *os.File
	done            chan struct{}
}

func newApp(dir string) *App {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return &App{dir: dir, token: hex.EncodeToString(b), selected: 0, status: "Отключено"}
}

type savedProfile struct {
	Source   string `json:"source"`
	Nodes    []Node `json:"nodes"`
	Selected int    `json:"selected"`
}

func (a *App) readSource() error {
	b, e := os.ReadFile(filepath.Join(a.dir, "profile.dpapi"))
	if e != nil {
		return e
	}
	plain, e := unprotect(b)
	if e != nil {
		return e
	}
	var p savedProfile
	if e = json.Unmarshal(plain, &p); e != nil {
		return e
	}
	a.source = p.Source
	a.nodes = p.Nodes
	a.selected = p.Selected
	if a.selected < 0 || a.selected >= len(a.nodes) {
		a.selected = 0
	}
	return nil
}
func (a *App) saveProfile(source string, nodes []Node, selected int) error {
	data, e := json.Marshal(savedProfile{Source: source, Nodes: nodes, Selected: selected})
	if e != nil {
		return e
	}
	b, e := protect(data)
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(a.dir, "profile.dpapi"), b, 0600)
}
func normalizeLink(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "hiddify://import/") {
		s = strings.TrimPrefix(s, "hiddify://import/")
		if i := strings.Index(s, "#"); i >= 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSpace(s)
	if isShareLink(s) {
		return s, nil
	}
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("вставь ссылку подписки https://... или ссылку узла vless://, vmess:// и т. п.")
	}
	return s, nil
}
func getNodes(s string) ([]Node, error) {
	var nodes []Node
	var e error
	if isShareLink(s) {
		nodes, e = parseSubscription([]byte(s))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		b, err := download(ctx, s, 5<<20)
		if err != nil {
			return nil, fmt.Errorf("не удалось загрузить подписку: %w", err)
		}
		nodes, e = parseSubscription(b)
	}
	if e != nil {
		return nil, e
	}
	compatible := make([]Node, 0, len(nodes))
	skipped := map[string]bool{}
	for _, n := range nodes {
		if _, err := xrayOutbound(n); err == nil {
			compatible = append(compatible, n)
		} else {
			skipped[n.Protocol] = true
		}
	}
	if len(compatible) == 0 {
		protocols := []string{}
		for k := range skipped {
			protocols = append(protocols, k)
		}
		return nil, fmt.Errorf("в подписке нет серверов, совместимых с Xray (VLESS/Trojan/VMess); обнаружены: %s", strings.Join(protocols, ", "))
	}
	return compatible, nil
}
func (a *App) importLink(s string) (int, error) {
	s, e := normalizeLink(s)
	if e != nil {
		return 0, e
	}
	nodes, e := getNodes(s)
	if e != nil {
		return 0, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return 0, errors.New("сначала отключи VPN")
	}
	if e = a.saveProfile(s, nodes, 0); e != nil {
		return 0, fmt.Errorf("не удалось сохранить подписку защищённо: %w", e)
	}
	a.source = s
	a.nodes = nodes
	a.selected = 0
	a.note = "Подписка сохранена на этом компьютере (Windows DPAPI)"
	return len(nodes), nil
}
func (a *App) updateNodes() error {
	a.mu.Lock()
	s := a.source
	a.mu.Unlock()
	if s == "" {
		return errors.New("сначала добавь ссылку")
	}
	nodes, e := getNodes(s)
	if e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return errors.New("обновление доступно после отключения")
	}
	a.nodes = nodes
	if a.selected >= len(nodes) {
		a.selected = 0
	}
	return a.saveProfile(a.source, a.nodes, a.selected)
}
func (a *App) start() error {
	if runtime.GOOS != "windows" {
		return errors.New("режим TUN доступен в Windows-сборке")
	}
	if !isAdmin() {
		return errors.New("для TUN нужны права администратора; запусти программу от имени администратора")
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return errors.New("VPN уже работает")
	}
	if len(a.nodes) == 0 {
		a.mu.Unlock()
		return errors.New("сначала импортируй ссылку на конфигурацию")
	}
	node := a.nodes[a.selected]
	a.status = "Подготовка подключения"
	a.mu.Unlock()
	if !a.haveCore() {
		return errors.New("Сначала установи Xray-core (через GitHub или официальный ZIP)")
	}
	cidrs := readRUCIDRs(filepath.Join(a.dir, "ru-cidrs.txt"))
	if len(cidrs) < 100 {
		// Для маршрутизации российских IP уже есть официальный geoip:ru.
		// Дополнительная загрузка списка не обязательна.
	}
	config := filepath.Join(a.dir, "active.json")
	if e := writeConfig(node, filepath.Join(a.dir, "ru-cidrs.txt"), config); e != nil {
		a.setError(e)
		return e
	}
	if e := checkCore(a.enginePath(), config); e != nil {
		_ = os.Remove(config)
		a.setError(e)
		return e
	}
	// Пока системная сеть не затронута, проверяем настоящий VLESS/XHTTP CONNECT.
	// При ошибке TUN не запускаем: интернет остаётся в прежнем состоянии.
	a.mu.Lock()
	a.status = "Проверяю VPN-сервер до включения TUN…"
	a.mu.Unlock()
	proxyIP, e := a.preflight(node)
	if e != nil {
		_ = os.Remove(config)
		a.setError(e)
		return e
	}
	lf, e := os.OpenFile(filepath.Join(a.dir, "engine.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		_ = os.Remove(config)
		a.setError(e)
		return e
	}
	cmd := exec.Command(a.enginePath(), "run", "-c", config)
	cmd.Dir = filepath.Dir(a.enginePath())
	cmd.Stdout = lf
	cmd.Stderr = lf
	hideWindow(cmd)
	if e = cmd.Start(); e != nil {
		lf.Close()
		_ = os.Remove(config)
		a.setError(e)
		return e
	}
	a.mu.Lock()
	a.cmd = cmd
	a.logFile = lf
	a.done = make(chan struct{})
	done := a.done
	a.running = true
	a.confirmed = false
	a.proxyExpectedIP = proxyIP
	a.status = "TUN запущен; проверяю системный IP и российские сайты…"
	if proxyIP != "" {
		a.note = "Проверка зарубежного маршрута ДО TUN: IP " + proxyIP
	}
	if len(cidrs) < 100 && proxyIP == "" {
		a.note = "RU IP-список пока не скачан: .ru направляются напрямую, но некоторые российские IP могут идти через VPN"
	} else if proxyIP == "" {
		a.note = fmt.Sprintf("RU-адреса: %d сетей; домены .ru/.рф/.su напрямую", len(cidrs))
	}
	a.timer = time.AfterFunc(90*time.Second, func() {
		a.mu.Lock()
		mustStop := a.running && !a.confirmed && a.cmd == cmd
		a.mu.Unlock()
		if mustStop {
			a.stop("Автоматический откат: подключение не подтверждено")
		}
	})
	a.mu.Unlock()
	go a.verifyAfterTun(cmd, proxyIP)
	go func() {
		err := cmd.Wait()
		a.mu.Lock()
		if a.cmd == cmd {
			a.cmd = nil
			a.running = false
			if a.timer != nil {
				a.timer.Stop()
				a.timer = nil
			}
			if err != nil && strings.Contains(a.status, "Подключ") {
				a.status = "Отключено — движок завершился: " + safeLog(err.Error())
			} else if !strings.Contains(a.status, "откат") && !strings.Contains(a.status, "TUN отключён") {
				a.status = "Отключено"
			}
			a.note = ""
		}
		if a.logFile == lf {
			lf.Close()
			a.logFile = nil
		}
		a.mu.Unlock()
		_ = os.Remove(config)
		close(done)
	}()
	return nil
}
func (a *App) stop(msg string) {
	a.mu.Lock()
	cmd := a.cmd
	done := a.done
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.confirmed = false
	a.proxyExpectedIP = ""
	a.status = msg
	a.running = false
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		sent := gracefulStop(cmd.Process)
		if sent && done != nil {
			select {
			case <-done:
				return
			case <-time.After(6 * time.Second):
			}
		}
		// Только если штатное завершение не получилось.
		_ = cmd.Process.Kill()
		if done != nil {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	}
}
func (a *App) setError(err error) {
	a.mu.Lock()
	a.status = "Ошибка: " + safeLog(err.Error())
	a.mu.Unlock()
}
func (a *App) statusJSON() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	nodes := []map[string]string{}
	for i, n := range a.nodes {
		nodes = append(nodes, map[string]string{"name": n.Name, "protocol": n.Protocol, "index": fmt.Sprint(i)})
	}
	return map[string]any{"status": a.status, "running": a.running, "confirmed": a.confirmed, "core": a.haveCore(), "nodes": nodes, "selected": a.selected, "saved": a.source != "", "note": a.note, "ruNetworks": len(readRUCIDRs(filepath.Join(a.dir, "ru-cidrs.txt"))), "engineVersion": engineVersion}
}

// Раздел 5. Локальный HTTP-интерфейс без удалённого доступа.
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, strings.ReplaceAll(indexHTML, "__LOCAL_SESSION_TOKEN__", a.token))
	})
	api := func(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if r.Header.Get("X-Neona-Token") != a.token {
				http.Error(w, `{"error":"доступ запрещён"}`, 403)
				return
			}
			if e := fn(w, r); e != nil {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			}
		}
	}
	ok := func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(map[string]any{"ok": true}) }
	mux.HandleFunc("GET /api/status", api(func(w http.ResponseWriter, r *http.Request) error { return json.NewEncoder(w).Encode(a.statusJSON()) }))
	mux.HandleFunc("POST /api/import", api(func(w http.ResponseWriter, r *http.Request) error {
		var q struct {
			Link string `json:"link"`
		}
		if e := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&q); e != nil {
			return e
		}
		_, e := a.importLink(q.Link)
		if e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/refresh", api(func(w http.ResponseWriter, r *http.Request) error {
		if e := a.updateNodes(); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/select", api(func(w http.ResponseWriter, r *http.Request) error {
		var q struct {
			Index int `json:"index"`
		}
		if e := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&q); e != nil {
			return e
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.running {
			return errors.New("сначала отключи VPN")
		}
		if q.Index < 0 || q.Index >= len(a.nodes) {
			return errors.New("неверный номер сервера")
		}
		a.selected = q.Index
		if e := a.saveProfile(a.source, a.nodes, a.selected); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/start", api(func(w http.ResponseWriter, r *http.Request) error {
		if e := a.start(); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/stop", api(func(w http.ResponseWriter, r *http.Request) error {
		a.stop("Отключено пользователем")
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/confirm", api(func(w http.ResponseWriter, r *http.Request) error { a.confirm(); ok(w); return nil }))
	mux.HandleFunc("POST /api/core", api(func(w http.ResponseWriter, r *http.Request) error {
		a.mu.Lock()
		running := a.running
		a.mu.Unlock()
		if running {
			return errors.New("отключи VPN перед обновлением движка")
		}
		if e := a.ensureCore(); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/core-upload", api(func(w http.ResponseWriter, r *http.Request) error {
		a.mu.Lock()
		running := a.running
		a.mu.Unlock()
		if running {
			return errors.New("отключи VPN перед установкой движка")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 75<<20)
		if e := r.ParseMultipartForm(75 << 20); e != nil {
			return e
		}
		f, _, e := r.FormFile("file")
		if e != nil {
			return e
		}
		defer f.Close()
		data, e := io.ReadAll(io.LimitReader(f, 70<<20))
		if e != nil {
			return e
		}
		if e = a.installOfficial(data); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/ru-update", api(func(w http.ResponseWriter, r *http.Request) error {
		if e := a.updateRUCIDRs(); e != nil {
			return e
		}
		ok(w)
		return nil
	}))
	mux.HandleFunc("POST /api/quit", api(func(w http.ResponseWriter, r *http.Request) error {
		a.stop("Приложение закрыто")
		ok(w)
		go func() { time.Sleep(300 * time.Millisecond); os.Exit(0) }()
		return nil
	}))
	return mux
}
