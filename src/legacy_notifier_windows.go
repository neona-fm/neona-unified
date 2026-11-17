//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Останавливаем ТОЛЬКО наблюдатель старых Neona Unified 1.0.x.
// Не отправляем команду /shutdown: она остановила бы VPN и туннели.
// Вместо этого точечно завершаем Python-процесс, в командной строке которого
// находится имя именно старого service.py. Все иные Python-процессы оставляем.
func stopLegacyPythonNotifier() (int, error) {
	const script = `$ErrorActionPreference='Stop'; $n=0; Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" | Where-Object { $_.CommandLine -match 'neona_unified_service[.]py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $n++ }; Write-Output $n`
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	data, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return 0, fmt.Errorf("превышено время поиска старой службы")
	}
	if err != nil {
		return 0, fmt.Errorf("не удалось остановить старый наблюдатель: %v", err)
	}
	var n int
	if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &n); err != nil {
		return 0, fmt.Errorf("неясный результат завершения старой службы")
	}
	return n, nil
}
