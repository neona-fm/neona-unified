package main

import "strings"

// Короткое уведомление внутри главного окна. Подробности доступны в логах.
func shortWarning(detail string) string {
	detail = safeLog(strings.ReplaceAll(strings.ReplaceAll(detail, "\n", " "), "\r", " "))
	if strings.HasPrefix(detail, "MCP:") {
		return "Один из MCP-туннелей потерял связь; подробности в диагностике"
	}
	if strings.Contains(detail, "VPN") || strings.Contains(detail, "Xray") {
		return "Процесс VPN отключился; подробности в журнале VPN"
	}
	return "Проблема соединения; подробности в диагностике"
}
