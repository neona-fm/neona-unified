package main

// Первая настройка отдельного профиля объединённой программы.
// Копирует рабочие данные VPN 1.5, не меняя прежнюю установку.
import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func migrateProfile(destination, source string) error {
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	names := []string{"profile.dpapi", "ru-cidrs.txt", "core/xray.exe", "core/geoip.dat", "core/geosite.dat", "core/wintun.dll"}
	for _, name := range names {
		old := filepath.Join(source, filepath.FromSlash(name))
		target := filepath.Join(destination, filepath.FromSlash(name))
		if _, err := os.Stat(target); err == nil {
			continue
		} // настройки нового профиля не перезаписывать
		src, err := os.Open(old)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("чтение исходного VPN: %w", err)
		}
		stat, err := src.Stat()
		if err != nil {
			src.Close()
			return err
		}
		if stat.IsDir() {
			src.Close()
			continue
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			src.Close()
			return err
		}
		tmp := target + ".part"
		dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			src.Close()
			return err
		}
		_, copied := io.Copy(dst, src)
		closeErr := dst.Close()
		src.Close()
		if copied != nil {
			os.Remove(tmp)
			return copied
		}
		if closeErr != nil {
			os.Remove(tmp)
			return closeErr
		}
		if err = os.Rename(tmp, target); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}
