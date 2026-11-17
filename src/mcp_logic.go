package main

// Мониторинг клиента tunnel-client v0.0.20. Полный health endpoint
// сообщает состояние опросов OpenAI, а /readyz проверяет лишь локальную готовность.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type tunnelSnapshot struct {
	Ready     bool
	Online    bool
	Level     string // green, amber, red
	Label     string
	PollAge   time.Duration
	MCPStatus string
}

func extractObject(v any, keys ...string) map[string]any {
	x, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range keys {
		x, ok = x[k].(map[string]any)
		if !ok {
			return nil
		}
	}
	return x
}
func textField(v any) string { x, _ := v.(string); return x }
func boolField(v any) bool   { x, _ := v.(bool); return x }
func assessTunnelHealth(payload []byte, now time.Time) (t tunnelSnapshot, err error) {
	var raw map[string]any
	if err = json.Unmarshal(payload, &raw); err != nil {
		return t, err
	}
	t.Ready = boolField(raw["ready"]) && boolField(raw["live"])
	if !t.Ready {
		t.Level = "red"
		t.Label = "Локальный клиент не готов"
		return t, nil
	}
	comps := extractObject(raw, "components")
	if comps == nil {
		t.Level = "amber"
		t.Label = "Есть локальная готовность; удалённая связь неизвестна"
		return t, nil
	}
	cp := extractObject(comps, "control-plane")
	if cp == nil {
		t.Level = "amber"
		t.Label = "Нет сведений об удалённом сервере; ждём проверки"
		return t, nil
	}
	details := extractObject(cp, "details")
	last := textField(details["last_success"])
	if last == "" {
		t.Level = "amber"
		t.Label = "Ожидаем подтверждения удалённой связи"
		return t, nil
	}
	stamp, parseErr := time.Parse(time.RFC3339Nano, last)
	if parseErr != nil {
		t.Level = "amber"
		t.Label = "Неверное время последнего опроса"
		return t, nil
	}
	t.PollAge = now.Sub(stamp)
	// Однократный сбой control-plane при недавнем успешном ответе
	// не означает, что действующее MCP-подключение уже недоступно.
	if textField(cp["status"]) != "ok" {
		failures, _ := details["consecutive_failures"].(float64)
		if t.PollAge >= 0 && t.PollAge <= 90*time.Second && failures < 3 {
			t.Online = true
			t.Level = "amber"
			t.Label = "Сервер OpenAI отвечает нестабильно; проверяю повторно"
			return t, nil
		}
		t.Level = "red"
		t.Label = "Нет подтверждения связи с OpenAI (control plane)"
		return t, nil
	}
	if t.PollAge > 90*time.Second {
		t.Level = "red"
		t.Label = fmt.Sprintf("Нет ответа OpenAI уже %ds", int(t.PollAge.Seconds()))
		return t, nil
	}
	if t.PollAge < -30*time.Second {
		t.Level = "amber"
		t.Label = "Время компьютера отличается от сервера"
		return t, nil
	}
	t.Online = true
	mp := extractObject(comps, "mcp")
	t.MCPStatus = textField(mp["status"])
	if t.MCPStatus != "ok" {
		t.Level = "amber"
		t.Label = "OpenAI на связи; MCP ещё не подтверждён"
		return t, nil
	}
	deliver := extractObject(comps, "response-delivery")
	if deliver != nil {
		if status := textField(deliver["status"]); status != "ok" && status != "unknown" && status != "" {
			t.Level = "amber"
			t.Label = "Связь есть; доставка ответов: " + strings.TrimSpace(status)
			return t, nil
		}
	}
	t.Level = "green"
	t.Label = "OpenAI и MCP доступны"
	return t, nil
}
