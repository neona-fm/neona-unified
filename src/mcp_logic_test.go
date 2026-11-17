package main

import (
	"fmt"
	"testing"
	"time"
)

func TestHealthRemoteStale(t *testing.T) {
	now := time.Date(2026, 11, 16, 20, 0, 0, 0, time.UTC)
	for _, v := range []struct {
		age          int
		state, level string
	}{
		{5, "ok", "green"}, {200, "ok", "red"}, {5, "unknown", "amber"},
	} {
		data := fmt.Sprintf(`{"ready":true,"live":true,"components":{"control-plane":{"status":"ok","details":{"last_success":"%s"}},"mcp":{"status":"%s"}}}`, now.Add(-time.Duration(v.age)*time.Second).Format(time.RFC3339), v.state)
		got, err := assessTunnelHealth([]byte(data), now)
		if err != nil || got.Level != v.level {
			t.Fatalf("age=%d state=%s got=%#v err=%v", v.age, v.state, got, err)
		}
	}
}
func TestHealthMissingRemote(t *testing.T) {
	got, _ := assessTunnelHealth([]byte(`{"ready":true,"live":true}`), time.Now())
	if got.Level != "amber" {
		t.Fatal(got)
	}
}

func TestTransientControlPlaneFailureIsNotOutage(t *testing.T) {
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	data := fmt.Sprintf(`{"ready":true,"live":true,"components":{"control-plane":{"status":"error","details":{"last_success":"%s","consecutive_failures":1}},"mcp":{"status":"ok"}}}`, now.Add(-15*time.Second).Format(time.RFC3339))
	got, err := assessTunnelHealth([]byte(data), now)
	if err != nil || !got.Online || got.Level != "amber" {
		t.Fatalf("transient failure must not be terminal: %#v %v", got, err)
	}
}
func TestSustainedControlPlaneFailure(t *testing.T) {
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	data := fmt.Sprintf(`{"ready":true,"live":true,"components":{"control-plane":{"status":"error","details":{"last_success":"%s","consecutive_failures":5}}}}`, now.Add(-120*time.Second).Format(time.RFC3339))
	got, err := assessTunnelHealth([]byte(data), now)
	if err != nil || got.Online || got.Level != "red" {
		t.Fatalf("sustained failure not detected: %#v %v", got, err)
	}
}
