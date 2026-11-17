package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Проверка VLESS/XHTTP без системного TUN. Не меняет сетевые настройки Windows.
// Только при успешном HTTP CONNECT через Xray разрешаем запуск TUN.
// При проверке не используем DoH через ещё не проверенный proxy: это замыкало DNS на недоступный канал.
func makeProbeConfig(node Node, port int) (map[string]any, error) {
	out, err := xrayOutbound(node)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "info", "access": "none", "maskAddress": "half"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "http", "tag": "probe-in",
			"settings": map[string]any{"allowTransparent": false},
		}},
		"outbounds": []any{out, map[string]any{"tag": "direct", "protocol": "freedom"}},
	}, nil
}

func availableLoopbackPort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(ctx context.Context, addr string, procExited <-chan error) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-procExited:
			if err == nil {
				return errors.New("Xray неожиданно завершил проверку")
			}
			return fmt.Errorf("Xray не запустил тестовый прокси: %w", err)
		case <-ctx.Done():
			return errors.New("Тестовый локальный прокси Xray не открылся")
		case <-ticker.C:
			c, e := net.DialTimeout("tcp4", addr, 150*time.Millisecond)
			if e == nil {
				c.Close()
				return nil
			}
		}
	}
}

// HTTP CONNECT через локальный Xray — тест без TUN. Результат проверки и ошибки
// записываем отдельно от данных подписки. Успех любого из независимых адресов
// подтверждает работу прокси, но IP показываем только если получили настоящий адрес.
func probeHTTP(proxyPort int, timeout time.Duration, log io.Writer) (string, error) {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 12 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr}
	targets := []struct{ name, endpoint string }{
		{"Cloudflare geo", "https://www.cloudflare.com/cdn-cgi/trace"},
		{"Public IP (ipinfo)", "https://ipinfo.io/json"},
		{"Public IP (ipify)", "https://api.ipify.org/"},
		{"Google connectivity", "https://www.gstatic.com/generate_204"},
	}
	reachable := false
	var errs []string
	for _, target := range targets {
		began := time.Now()
		rsp, err := client.Get(target.endpoint)
		if err != nil {
			msg := safeLog(err.Error())
			if msg == "" {
				msg = "соединение не установлено"
			}
			io.WriteString(log, fmt.Sprintf("[Neona test] %s: ERROR (%s): %s\n", target.name, time.Since(began).Round(time.Millisecond), msg))
			errs = append(errs, fmt.Sprintf("%s: %s", target.name, msg))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(rsp.Body, 8192))
		_ = rsp.Body.Close()
		io.WriteString(log, fmt.Sprintf("[Neona test] %s: HTTP %d (%s)\n", target.name, rsp.StatusCode, time.Since(began).Round(time.Millisecond)))
		if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
			errs = append(errs, fmt.Sprintf("%s: HTTP %d", target.name, rsp.StatusCode))
			continue
		}
		reachable = true
		switch target.name {
		case "Cloudflare geo":
			info := parseTrace(body)
			if info.IP != "" {
				io.WriteString(log, fmt.Sprintf("[Neona test] Proxy exit IP %s, country %s (Cloudflare)\n", info.IP, info.Country))
				if info.Country == "RU" {
					return "", errors.New("VPN-сервер отвечает, но его выход определяется как Россия (RU)")
				}
				return info.IP, nil
			}
		case "Public IP (ipinfo)":
			var p struct {
				IP      string `json:"ip"`
				Country string `json:"country"`
			}
			if json.Unmarshal(body, &p) == nil && net.ParseIP(p.IP) != nil {
				io.WriteString(log, fmt.Sprintf("[Neona test] Proxy exit IP %s, country %s (ipinfo)\n", p.IP, p.Country))
				if strings.EqualFold(p.Country, "RU") {
					return "", errors.New("VPN-сервер отвечает, но его выход определяется как Россия (RU)")
				}
				return p.IP, nil
			}
		case "Public IP (ipify)":
			if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
				io.WriteString(log, fmt.Sprintf("[Neona test] Proxy exit IP %s (ipify)\n", ip.String()))
				return ip.String(), nil
			}
		}
	}
	if reachable {
		return "", errors.New("VPN смог открыть HTTPS, но не удалось определить его внешний IP. Запуск TUN отменён, чтобы не потерять интернет")
	}
	return "", fmt.Errorf("предварительный тест через Xray не прошёл (TUN не включён). Подробности в probe.log: %s", strings.Join(errs, "; "))
}

// Прямая диагностика адреса сервера не меняет маршрутов и не является
// доказательством корректности VLESS/XHTTP — проверяет только TCP-порт.
func logServerTCP(node Node, w io.Writer) {
	host := strings.TrimSpace(asStr(node.Out["server"]))
	if host == "" {
		return
	}
	port := asStr(node.Out["server_port"])
	if port == "" {
		port = strconv.Itoa(443)
	}
	began := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 4*time.Second)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("[Neona test] Direct TCP to VPN server: FAILED (%s): %s\n", time.Since(began).Round(time.Millisecond), safeLog(err.Error())))
		return
	}
	c.Close()
	io.WriteString(w, fmt.Sprintf("[Neona test] Direct TCP to VPN server: OK (%s). VLESS/XHTTP not yet verified.\n", time.Since(began).Round(time.Millisecond)))
}

func (a *App) preflight(node Node) (string, error) {
	port, err := availableLoopbackPort()
	if err != nil {
		return "", err
	}
	config, err := makeProbeConfig(node, port)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(a.dir, "probe.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		return "", err
	}
	defer os.Remove(path)
	if err = checkCore(a.enginePath(), path); err != nil {
		return "", err
	}
	logPath := filepath.Join(a.dir, "probe.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", err
	}
	defer lf.Close()
	io.WriteString(lf, "[Neona test] Xray HTTP proxy preflight; no TUN / no system route changes.\n")
	logServerTCP(node, lf)
	cmd := exec.Command(a.enginePath(), "run", "-c", path)
	cmd.Dir = filepath.Dir(a.enginePath())
	cmd.Stdout = lf
	cmd.Stderr = lf
	hideWindow(cmd)
	if err = cmd.Start(); err != nil {
		return "", fmt.Errorf("не удалось запустить Xray для проверки: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err = waitPort(ctx, fmt.Sprintf("127.0.0.1:%d", port), exited); err != nil {
		return "", err
	}
	ip, err := probeHTTP(port, 16*time.Second, lf)
	if err != nil {
		io.WriteString(lf, "[Neona test] FAILED. Windows routing has not been changed.\n")
		_ = lf.Sync()
		return "", err
	}
	io.WriteString(lf, "[Neona test] SUCCESS: VPN proxy reached HTTPS destination. TUN can be attempted.\n")
	_ = lf.Sync()
	return ip, nil
}
