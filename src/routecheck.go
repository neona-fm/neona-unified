package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Раздел 6. Проверяем системный маршрут, минуя все HTTP/HTTPS proxy.
// Запуск процесса Xray и доступность сайтов сами по себе не подтверждают TUN.
type RouteIdentity struct {
	IP      string
	Country string
	Source  string
}

func parseTrace(body []byte) RouteIdentity {
	var r RouteIdentity
	for _, line := range strings.Split(string(body), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "ip":
			if net.ParseIP(kv[1]) != nil {
				r.IP = kv[1]
			}
		case "loc":
			if len(kv[1]) == 2 {
				r.Country = strings.ToUpper(kv[1])
			}
		}
	}
	if r.IP != "" || r.Country != "" {
		r.Source = "Cloudflare"
	}
	return r
}

func directHTTP() *http.Client {
	transport := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 8 * time.Second,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp4", addr)
		},
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func fetchSmall(c *http.Client, url string, max int64) ([]byte, int, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(data)) > max {
		return nil, resp.StatusCode, errors.New("слишком длинный ответ")
	}
	return data, resp.StatusCode, nil
}

func publicIPFromClient(client *http.Client) (RouteIdentity, error) {
	var errorsList []string
	if data, code, err := fetchSmall(client, "https://www.cloudflare.com/cdn-cgi/trace", 8192); err == nil && code == 200 {
		if r := parseTrace(data); r.IP != "" && r.Country != "" {
			return r, nil
		}
	} else if err != nil {
		errorsList = append(errorsList, "Cloudflare: "+safeLog(err.Error()))
	}
	if data, code, err := fetchSmall(client, "https://ipinfo.io/json", 8192); err == nil && code == 200 {
		var p struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
		}
		if json.Unmarshal(data, &p) == nil && net.ParseIP(p.IP) != nil && len(p.Country) == 2 {
			return RouteIdentity{IP: p.IP, Country: strings.ToUpper(p.Country), Source: "ipinfo"}, nil
		}
	} else if err != nil {
		errorsList = append(errorsList, "ipinfo: "+safeLog(err.Error()))
	}
	if data, code, err := fetchSmall(client, "https://api.ipify.org", 128); err == nil && code == 200 {
		ip := strings.TrimSpace(string(data))
		if net.ParseIP(ip) != nil {
			return RouteIdentity{IP: ip, Source: "ipify"}, nil
		}
	} else if err != nil {
		errorsList = append(errorsList, "ipify: "+safeLog(err.Error()))
	}
	return RouteIdentity{}, fmt.Errorf("не удалось определить системный IP: %s", strings.Join(errorsList, "; "))
}

func checkRussianSite(client *http.Client) error {
	// 2xx/3xx: сайт доступен. Редиректы не открываем, чтобы исключить другой маршрут.
	_, code, err := fetchSmall(client, "https://ya.ru/", 256)
	if err != nil {
		return err
	}
	if code < 200 || code >= 400 {
		return fmt.Errorf("ya.ru вернул HTTP %d", code)
	}
	return nil
}

// Значение country идёт от реального внешнего IP, а не от службы геолокации Windows.
func evaluateSystemRoute(expectedIP string, actual RouteIdentity, ruOK bool) error {
	if actual.Country == "RU" {
		return errors.New("системный выход всё ещё Россия (RU): трафик обходит зарубежный VPN")
	}
	if actual.IP == "" {
		return errors.New("не удалось измерить системный IP")
	}
	if expectedIP != "" && actual.IP != expectedIP {
		return fmt.Errorf("IP через VPN %s, но системный IP %s: TUN не обеспечил тот же выход", expectedIP, actual.IP)
	}
	if actual.Country == "" && expectedIP == "" {
		return errors.New("зарубежный системный маршрут не подтверждён")
	}
	if !ruOK {
		return errors.New("зарубежный маршрут работает, но российский ya.ru недоступен")
	}
	return nil
}

func probeSystemRoute() (RouteIdentity, bool, error) {
	client := directHTTP()
	identity, err := publicIPFromClient(client)
	if err != nil {
		return RouteIdentity{}, false, err
	}
	if identity.Country == "RU" {
		return identity, false, nil
	}
	ruErr := checkRussianSite(client)
	return identity, ruErr == nil, ruErr
}

// Диагностический снимок маршрутов Windows. Только чтение; никакого route add/del.
func (a *App) captureWindowsRoutes() {
	if err := os.MkdirAll(a.dir, 0700); err != nil {
		return
	}
	cmd := exec.Command("route.exe", "print", "-4")
	out, err := cmd.CombinedOutput()
	if err != nil {
		out = append(out, []byte("\nroute.exe: "+err.Error())...)
	}
	_ = os.WriteFile(filepath.Join(a.dir, "routes.log"), out, 0600)
}

func (a *App) verifyAfterTun(cmdID *exec.Cmd, expectedIP string) {
	time.Sleep(2500 * time.Millisecond)
	a.mu.Lock()
	active := a.cmd == cmdID && a.running
	a.mu.Unlock()
	if !active {
		return
	}
	a.captureWindowsRoutes()
	actual, ruOK, err := probeSystemRoute()
	a.mu.Lock()
	active = a.cmd == cmdID && a.running && !a.confirmed
	a.mu.Unlock()
	if !active {
		return
	}
	resultErr := evaluateSystemRoute(expectedIP, actual, ruOK)
	if err != nil && resultErr == nil {
		resultErr = err
	}
	if resultErr != nil {
		// При доказанном российском системном IP останавливаем TUN автоматически.
		if actual.Country == "RU" {
			a.stop("TUN отключён: системный IP остался RU")
			a.mu.Lock()
			a.note = "Системный IP " + actual.IP + ", страна RU (" + actual.Source + "). Смотри routes.log; откат выполнен."
			a.mu.Unlock()
			return
		}
		a.mu.Lock()
		if a.cmd == cmdID && a.running {
			a.note = resultErr.Error() + "; проверь routes.log и engine.log"
			a.status = "TUN запущен, но маршрут пока не подтверждён"
		}
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cmd != cmdID || !a.running {
		return
	}
	a.confirmed = true
	a.status = "Проверено: системный IP " + actual.IP + " (" + actual.Country + "); ya.ru доступен"
	a.note = "Системный маршрут подтверждён по " + actual.Source + ". Россия — напрямую по правилам Xray."
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}

// Кнопка больше не подтверждает VPN вслепую: повторно измеряет системный выход.
func (a *App) confirm() error {
	a.mu.Lock()
	active := a.running
	expected := a.proxyExpectedIP
	a.mu.Unlock()
	if !active {
		return errors.New("VPN пока не запущен")
	}
	actual, ruOK, err := probeSystemRoute()
	if err != nil {
		return err
	}
	if err = evaluateSystemRoute(expected, actual, ruOK); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return errors.New("VPN был отключён во время проверки")
	}
	a.confirmed = true
	a.status = "Проверено: системный IP " + actual.IP + " (" + actual.Country + ")"
	a.note = "Иностранный IP подтверждён; российский ya.ru отвечает."
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	return nil
}
