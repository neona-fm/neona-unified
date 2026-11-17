//go:build !windows

package main

import (
	"os"
	"os/exec"
)

func isAdmin() bool            { return true }
func requestAdmin() error      { return nil }
func openBrowser(url string)   {}
func hideWindow(cmd *exec.Cmd) {}

func launchUI(a *App) {
	println("Neona Split VPN: интерфейс доступен только в Windows")
}

func gracefulStop(p *os.Process) bool { return false }
