//go:build !windows

package main

func protect(b []byte) ([]byte, error)   { return append([]byte{}, b...), nil }
func unprotect(b []byte) ([]byte, error) { return append([]byte{}, b...), nil }
