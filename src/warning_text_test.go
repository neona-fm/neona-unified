package main

import (
	"strings"
	"testing"
)

func TestWarningsAreShortAndNonSensitive(t *testing.T) {
	for _, v := range []string{"MCP: token secret suddenly offline", "VPN: private.example.ru", "Other secret"} {
		got := shortWarning(v)
		if len(got) > 160 || strings.Contains(got, "secret") || strings.Contains(got, "private.example") {
			t.Fatalf("unsafe warning: %s", got)
		}
	}
}
