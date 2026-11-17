//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var shell32 = syscall.NewLazyDLL("shell32.dll")
var isAdminProc = shell32.NewProc("IsUserAnAdmin")

func isAdmin() bool { r, _, _ := isAdminProc.Call(); return r != 0 }
func requestAdmin() error {
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	name, _ := syscall.UTF16PtrFromString(executable)
	proc := shell32.NewProc("ShellExecuteW")
	result, _, err := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(name)), 0, 0, 1)
	if result <= 32 {
		return err
	}
	return nil
}
func openBrowser(url string) {
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

// При остановке отправляем Xray CTRL+BREAK, чтобы он успел снять TUN,
// системные маршруты и фильтры WFP. Kill используется лишь как крайняя мера.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000010 | 0x00000200}
}

func gracefulStop(p *os.Process) bool {
	if p == nil {
		return false
	}
	kernel := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel.NewProc("AttachConsole")
	detach := kernel.NewProc("FreeConsole")
	handler := kernel.NewProc("SetConsoleCtrlHandler")
	generate := kernel.NewProc("GenerateConsoleCtrlEvent")
	attached, _, _ := attach.Call(uintptr(p.Pid))
	if attached == 0 {
		return false
	}
	handler.Call(0, 1)
	sent, _, _ := generate.Call(1, uintptr(p.Pid))
	detach.Call()
	handler.Call(0, 0)
	return sent != 0
}

func launchUI(a *App) {
	if !isAdmin() {
		if err := requestAdmin(); err == nil {
			return
		}
	}
	showNativeUI(a)
}
