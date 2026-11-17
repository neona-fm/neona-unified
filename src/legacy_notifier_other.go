//go:build !windows

package main

func stopLegacyPythonNotifier() (int, error) { return 0, nil }
