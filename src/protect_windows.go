//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

// Раздел 7. Windows DPAPI: ссылка на подписку зашифрована для текущей учётной записи.
type dataBlob struct {
	size uint32
	data *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")

func crypt(raw []byte, encrypt bool) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("пустая ссылка")
	}
	in := dataBlob{size: uint32(len(raw)), data: &raw[0]}
	var out dataBlob
	var proc *syscall.LazyProc
	if encrypt {
		proc = crypt32.NewProc("CryptProtectData")
	} else {
		proc = crypt32.NewProc("CryptUnprotectData")
	}
	args := []uintptr{uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out))}
	if !encrypt {
		args = []uintptr{uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out))}
	}
	r, _, err := proc.Call(args...)
	if r == 0 {
		return nil, err
	}
	defer kernel32.NewProc("LocalFree").Call(uintptr(unsafe.Pointer(out.data)))
	ret := make([]byte, out.size)
	copy(ret, unsafe.Slice(out.data, int(out.size)))
	return ret, nil
}
func protect(b []byte) ([]byte, error)   { return crypt(b, true) }
func unprotect(b []byte) ([]byte, error) { return crypt(b, false) }
