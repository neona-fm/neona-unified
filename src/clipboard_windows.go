//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func logTail(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return "Журнал отсутствует"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "Журнал недоступен"
	}
	start := st.Size() - int64(max)
	if start < 0 {
		start = 0
	}
	_, _ = f.Seek(start, 0)
	b := make([]byte, max)
	n, _ := f.Read(b)
	if n < 0 {
		n = 0
	}
	return string(b[:n])
}
func diagnostics(u *unifiedController) string {
	s := []string{"Neona Unified — диагностика", "Время: " + time.Now().Format(time.RFC3339), "VPN: " + u.liveStatus(), u.describe(tunnelWindows), u.describe(tunnelChrome)}
	for _, f := range []struct{ name, path string }{
		{"События подключений", filepath.Join(u.app.dir, "connection-events.log")},
		{"VPN probe.log", filepath.Join(u.app.dir, "probe.log")},
		{"VPN engine.log", filepath.Join(u.app.dir, "engine.log")},
		{"Windows MCP", filepath.Join(u.mcp.logsDir, "windows.log")},
		{"Chrome MCP", filepath.Join(u.mcp.logsDir, "chrome.log")},
	} {
		s = append(s, "\n--- "+f.name+" ---\n"+logTail(f.path, 12000))
	}
	return strings.Join(s, "\n")
}
func copyToClipboard(s string) error {
	if s == "" {
		return errors.New("нечего копировать")
	}
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return err
	}
	mem := syscall.NewLazyDLL("kernel32.dll")
	h, _, e := mem.NewProc("GlobalAlloc").Call(0x0002, uintptr(len(u)*2))
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %w", e)
	}
	released := false
	defer func() {
		if !released {
			mem.NewProc("GlobalFree").Call(h)
		}
	}()
	p, _, e := mem.NewProc("GlobalLock").Call(h)
	if p == 0 {
		return fmt.Errorf("GlobalLock: %w", e)
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(u)), u)
	mem.NewProc("GlobalUnlock").Call(h)
	clip := syscall.NewLazyDLL("user32.dll")
	opened, _, e := clip.NewProc("OpenClipboard").Call(0)
	if opened == 0 {
		return fmt.Errorf("OpenClipboard: %w", e)
	}
	defer clip.NewProc("CloseClipboard").Call()
	ok, _, e := clip.NewProc("EmptyClipboard").Call()
	if ok == 0 {
		return fmt.Errorf("EmptyClipboard: %w", e)
	}
	set, _, e := clip.NewProc("SetClipboardData").Call(13, h)
	if set == 0 {
		return fmt.Errorf("SetClipboardData: %w", e)
	}
	released = true
	return nil
}
func copyDiagnostics(u *unifiedController) error { return copyToClipboard(diagnostics(u)) }

func readClipboardText() (string, error) {
	user := syscall.NewLazyDLL("user32.dll")
	open, _, e := user.NewProc("OpenClipboard").Call(0)
	if open == 0 {
		return "", fmt.Errorf("OpenClipboard: %w", e)
	}
	defer user.NewProc("CloseClipboard").Call()
	h, _, e := user.NewProc("GetClipboardData").Call(13)
	if h == 0 {
		return "", fmt.Errorf("в буфере нет текстовой ссылки: %w", e)
	}
	mem := syscall.NewLazyDLL("kernel32.dll")
	p, _, e := mem.NewProc("GlobalLock").Call(h)
	if p == 0 {
		return "", fmt.Errorf("GlobalLock: %w", e)
	}
	defer mem.NewProc("GlobalUnlock").Call(h)
	// Не читаем за границами выделенного блока даже если буфер повреждён.
	size, _, _ := mem.NewProc("GlobalSize").Call(h)
	if size < 2 || size > 2*1024*1024 {
		return "", errors.New("неподходящий размер текста в буфере")
	}
	data := unsafe.Slice((*uint16)(unsafe.Pointer(p)), int(size/2))
	i := 0
	for i < len(data) && data[i] != 0 {
		i++
	}
	return syscall.UTF16ToString(data[:i]), nil
}
