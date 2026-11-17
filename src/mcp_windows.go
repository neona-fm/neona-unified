//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Раздел MCP. Единственный видимый процесс — Neona Unified GUI.
// tunnel-client.exe (по одному на профиль) — необходимые фоновые сетевые процессы.
// Совместимость с DPAPI-хранилищем и портами исходного менеджера 0.3.5.
const (
	tunnelWindows = "windows"
	tunnelChrome  = "chrome"
)

type tunnelInfo struct {
	Level, Label  string
	Ready, Online bool
}
type mcpController struct {
	mu                        sync.Mutex
	dataFile, logsDir, binary string
	info                      map[string]tunnelInfo
}

func newMCPController() *mcpController {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		home, _ := os.UserHomeDir()
		local = filepath.Join(home, "AppData", "Local")
	}
	m := &mcpController{dataFile: filepath.Join(local, "NeonaMCP", "settings.json"), logsDir: filepath.Join(local, "NeonaMCP", "logs"), info: make(map[string]tunnelInfo)}
	m.binary = m.findBinary()
	for _, p := range []string{tunnelWindows, tunnelChrome} {
		m.info[p] = tunnelInfo{Level: "red", Label: "Отключён"}
	}
	return m
}
func (m *mcpController) findBinary() string {
	exe, _ := os.Executable()
	paths := []string{filepath.Dir(exe), filepath.Join(filepath.Dir(exe), ".."), `C:\NeonaMCP`}
	for _, root := range paths {
		matches, _ := filepath.Glob(filepath.Join(root, "client", "tunnel-client-*-windows-amd64", "tunnel-client.exe"))
		for i := len(matches) - 1; i >= 0; i-- {
			if stat, e := os.Stat(matches[i]); e == nil && !stat.IsDir() {
				return matches[i]
			}
		}
	}
	return filepath.Join(`C:\NeonaMCP`, "client", "tunnel-client-v0.0.20-windows-amd64", "tunnel-client.exe")
}
func (m *mcpController) readSettings() (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(m.dataFile)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]json.RawMessage), nil
	}
	if err != nil {
		return nil, err
	}
	var cfg map[string]json.RawMessage
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("не удалось прочитать настройки MCP: %w", err)
	}
	if cfg == nil {
		cfg = make(map[string]json.RawMessage)
	}
	return cfg, nil
}
func (m *mcpController) writeSettings(cfg map[string]json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(m.dataFile), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.dataFile + ".new"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.dataFile)
}
func (m *mcpController) getSavedSecrets() (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.readSettings()
	if err != nil {
		return "", "", err
	}
	read := func(k string) (string, error) {
		var encoded string
		if len(cfg[k]) == 0 {
			return "", nil
		}
		if err := json.Unmarshal(cfg[k], &encoded); err != nil {
			return "", err
		}
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err
		}
		plain, err := unprotect(b)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	api, err := read("runtime_key_dpapi")
	if err != nil {
		return "", "", err
	}
	chrome, err := read("chrome_token_dpapi")
	return api, chrome, err
}
func (m *mcpController) saveSecrets(api, chrome string) error {
	if strings.TrimSpace(api) == "" {
		return errors.New("укажи ключ OpenAI для MCP-туннелей")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.readSettings()
	if err != nil {
		return err
	}
	for k, v := range map[string]string{"runtime_key_dpapi": api, "chrome_token_dpapi": chrome} {
		if v == "" {
			delete(cfg, k)
			continue
		}
		protected, err := protect([]byte(strings.TrimSpace(v)))
		if err != nil {
			return err
		}
		s := base64.StdEncoding.EncodeToString(protected)
		b, _ := json.Marshal(s)
		cfg[k] = b
	}
	return m.writeSettings(cfg)
}
func (m *mcpController) pidFor(profile string) int {
	cfg, err := m.readSettings()
	if err != nil {
		return 0
	}
	var pids map[string]int
	_ = json.Unmarshal(cfg["pids"], &pids)
	return pids[profile]
}
func (m *mcpController) recordPID(profile string, pid int) error {
	cfg, err := m.readSettings()
	if err != nil {
		return err
	}
	var pids map[string]int
	_ = json.Unmarshal(cfg["pids"], &pids)
	if pids == nil {
		pids = make(map[string]int)
	}
	if pid > 0 {
		pids[profile] = pid
	} else {
		delete(pids, profile)
	}
	b, _ := json.Marshal(pids)
	cfg["pids"] = b
	return m.writeSettings(cfg)
}
func processImage(pid int) string {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	open := kernel.NewProc("OpenProcess")
	h, _, _ := open.Call(0x1000, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer kernel.NewProc("CloseHandle").Call(h)
	chars := uint32(32768)
	buf := make([]uint16, int(chars))
	found, _, _ := kernel.NewProc("QueryFullProcessImageNameW").Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&chars)))
	if found == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:chars])
}
func (m *mcpController) isOwned(pid int) bool {
	if pid <= 0 {
		return false
	}
	return strings.EqualFold(filepath.Clean(processImage(pid)), filepath.Clean(m.binary))
}
func portFor(profile string) int {
	if profile == tunnelWindows {
		return 8080
	}
	return 8081
}
func profileName(profile string) string {
	if profile == tunnelWindows {
		return "neona-windows"
	}
	return "neona-chrome"
}
func (m *mcpController) inspect(profile string) tunnelInfo {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	url := fmt.Sprintf("http://127.0.0.1:%d/health?details=true", portFor(profile))
	resp, err := client.Get(url)
	if err != nil {
		return tunnelInfo{Level: "red", Label: "Клиент не отвечает: " + safeLog(err.Error())}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return tunnelInfo{Level: "red", Label: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return tunnelInfo{Level: "red", Label: "Не читается диагностика"}
	}
	health, err := assessTunnelHealth(body, time.Now())
	if err != nil {
		return tunnelInfo{Level: "amber", Label: "Диагностика удалённой связи недоступна"}
	}
	return tunnelInfo{Level: health.Level, Label: health.Label, Ready: health.Ready, Online: health.Online}
}
func (m *mcpController) get(profile string) tunnelInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.info[profile]
}

// Только при нажатии кнопки: локальный снимок состояния двух туннелей.
func (m *mcpController) poll() {
	for _, p := range []string{tunnelWindows, tunnelChrome} {
		v := m.inspect(p)
		m.mu.Lock()
		m.info[p] = v
		m.mu.Unlock()
	}
}
func (m *mcpController) start(profile string) error {
	if profile != tunnelWindows && profile != tunnelChrome {
		return errors.New("неизвестный профиль")
	}
	if stat, err := os.Stat(m.binary); err != nil || stat.IsDir() {
		return fmt.Errorf("не найден tunnel-client.exe: %s", m.binary)
	}
	m.mu.Lock()
	cfg, err := m.readSettings()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	var pids map[string]int
	_ = json.Unmarshal(cfg["pids"], &pids)
	recorded := pids[profile]
	m.mu.Unlock()
	if recorded > 0 && m.isOwned(recorded) {
		return nil
	}
	current := m.inspect(profile)
	if current.Ready {
		return fmt.Errorf("порт %d уже обслуживается сторонним экземпляром; останови старый менеджер", portFor(profile))
	}
	api, chrome, err := m.getSavedSecrets()
	if err != nil {
		return err
	}
	if api == "" {
		return errors.New("не сохранён ключ MCP OpenAI")
	}
	if err = os.MkdirAll(m.logsDir, 0700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(m.logsDir, profile+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	env := append(os.Environ(), "CONTROL_PLANE_API_KEY="+api)
	if chrome != "" {
		env = append(env, "PLAYWRIGHT_MCP_EXTENSION_TOKEN="+chrome)
	}
	cmd := exec.Command(m.binary, "run", "--profile", profileName(profile), "--health.listen-addr", fmt.Sprintf("127.0.0.1:%d", portFor(profile)))
	cmd.Dir = filepath.Dir(m.binary)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	err = cmd.Start()
	_ = logFile.Close()
	if err != nil {
		return fmt.Errorf("запуск %s: %w", profile, err)
	}
	m.mu.Lock()
	err = m.recordPID(profile, cmd.Process.Pid)
	m.mu.Unlock()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
func (m *mcpController) awaitOnline(profile string, timeout time.Duration, keepGoing func() bool) error {
	deadline := time.Now().Add(timeout)
	var latest tunnelInfo
	for time.Now().Before(deadline) {
		if !keepGoing() {
			return errors.New("Запуск остановлен пользователем")
		}
		latest = m.inspect(profile)
		m.mu.Lock()
		m.info[profile] = latest
		m.mu.Unlock()
		if latest.Ready && latest.Online {
			return nil
		}
		time.Sleep(1600 * time.Millisecond)
	}
	return fmt.Errorf("%s: OpenAI не подтвердил связь: %s", profile, latest.Label)
}
func (m *mcpController) stop(profile string) error {
	m.mu.Lock()
	pid := m.pidFor(profile)
	m.mu.Unlock()
	if pid > 0 && m.isOwned(pid) {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "taskkill.exe", "/PID", fmt.Sprint(pid), "/T", "/F")
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		_, _ = command.CombinedOutput()
	}
	m.mu.Lock()
	err := m.recordPID(profile, 0)
	m.mu.Unlock()
	m.mu.Lock()
	m.info[profile] = tunnelInfo{Level: "red", Label: "Отключён"}
	m.mu.Unlock()
	return err
}
func (m *mcpController) stopAll() {
	_ = m.stop(tunnelChrome)
	_ = m.stop(tunnelWindows)
}
