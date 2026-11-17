//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Единая оркестрация двух оригинальных механизмов.
// Система маршрутизации Xray и preflight остаются из VPN 1.5.
// Параметры tunnel-client и хранилище ключей — из MCP Manager 0.3.5.
type unifiedController struct {
	app    *App
	mcp    *mcpController
	mu     sync.Mutex
	active bool
}

// Конструируем только управление по запросу. Фоновых наблюдателей нет.
func newUnifiedController(a *App) *unifiedController {
	return &unifiedController{app: a, mcp: newMCPController()}
}

func (u *unifiedController) startAll() error {
	u.mu.Lock()
	if u.active {
		u.mu.Unlock()
		return errors.New("последовательный запуск уже выполняется или соединение активно")
	}
	u.active = true
	u.mu.Unlock()
	success := false
	defer func() {
		if !success {
			u.mu.Lock()
			u.active = false
			u.mu.Unlock()
		}
	}()
	u.app.mu.Lock()
	running := u.app.running
	confirmed := u.app.confirmed
	u.app.mu.Unlock()
	if !running {
		if err := u.app.start(); err != nil {
			return fmt.Errorf("VPN: %w", err)
		}
		if !u.isActive() {
			u.app.stop("Запуск прерван")
			return errors.New("Запуск остановлен пользователем")
		}
	}
	if !confirmed {
		deadline := time.Now().Add(100 * time.Second)
		for time.Now().Before(deadline) {
			u.app.mu.Lock()
			running = u.app.running
			confirmed = u.app.confirmed
			status := u.app.status
			u.app.mu.Unlock()
			if confirmed {
				break
			}
			if !u.isActive() {
				return errors.New("Запуск остановлен пользователем")
			}
			if !running {
				return fmt.Errorf("VPN отключился до подтверждения: %s", status)
			}
			time.Sleep(1100 * time.Millisecond)
		}
		if !confirmed {
			return errors.New("VPN не подтвердил системный зарубежный IP и доступ к ya.ru. Туннели не запускались")
		}
	}
	for _, profile := range []string{tunnelWindows, tunnelChrome} {
		if !u.isActive() {
			return errors.New("Запуск остановлен пользователем")
		}
		if err := u.mcp.start(profile); err != nil {
			return err
		}
		// Проверка доступности MCP выполняется один раз в момент запуска.
		if err := u.mcp.awaitOnline(profile, 55*time.Second, u.isActive); err != nil {
			return err
		}
	}
	u.mu.Lock()
	if !u.active {
		u.mu.Unlock()
		return errors.New("Запуск остановлен пользователем")
	}
	u.mu.Unlock()
	success = true
	return nil
}
func (u *unifiedController) isActive() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.active }
func (u *unifiedController) stopAll() {
	u.mu.Lock()
	u.active = false
	u.mu.Unlock()
	u.mcp.stopAll()
	u.app.stop("Отключено пользователем")
}
func (u *unifiedController) close() {
	u.stopAll()
}
func (u *unifiedController) liveStatus() string {
	u.app.mu.Lock()
	running, confirmed, status := u.app.running, u.app.confirmed, u.app.status
	u.app.mu.Unlock()
	if !running {
		return "VPN: отключён — " + status
	}
	if !confirmed {
		return "VPN: идёт проверка маршрута — " + status
	}
	return "VPN: " + status
}
func (u *unifiedController) describe(profile string) string {
	s := u.mcp.get(profile)
	name := "Windows MCP"
	if profile == tunnelChrome {
		name = "Chrome MCP"
	}
	pfx := "● "
	if s.Level == "green" {
		pfx = "✓ "
	} else if s.Level == "amber" {
		pfx = "◐ "
	}
	return strings.TrimSpace(fmt.Sprintf("%s%s: %s", pfx, name, s.Label))
}
