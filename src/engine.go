package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Раздел 3. Только официальный Xray-core. ZIP проверяется по SHA-256 релиза.
const engineVersion = "26.10.31"
const engineURL = "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-windows-64.zip"
const engineSHA = "2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a"
const engineMirrorURL = "https://downloads.sourceforge.net/project/xray-core.mirror/v26.10.31/Xray-windows-64.zip"
const ipListURL = "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"

func download(ctx context.Context, link string, max int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", link, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "NeonaSplitVPN/1.5")
	client := &http.Client{Timeout: 60 * time.Second}
	rsp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", rsp.StatusCode)
	}
	if rsp.ContentLength > max {
		return nil, errors.New("превышен допустимый размер")
	}
	b, e := io.ReadAll(io.LimitReader(rsp.Body, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, errors.New("файл слишком большой")
	}
	return b, nil
}
func (a *App) enginePath() string { return filepath.Join(a.dir, "core", "xray.exe") }
func (a *App) haveCore() bool {
	for _, name := range []string{"xray.exe", "geoip.dat", "geosite.dat", "wintun.dll"} {
		i, e := os.Stat(filepath.Join(a.dir, "core", name))
		if e != nil || i.IsDir() || i.Size() == 0 {
			return false
		}
	}
	return true
}
func (a *App) installOfficial(data []byte) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != engineSHA {
		return errors.New("контрольная сумма ZIP не совпадает с официальным выпуском Xray 26.10.31")
	}
	zr, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return e
	}
	need := map[string]bool{"xray.exe": true, "geoip.dat": true, "geosite.dat": true, "wintun.dll": true}
	files := map[string][]byte{}
	for _, f := range zr.File {
		name := strings.ToLower(filepath.Base(f.Name))
		if !need[name] {
			continue
		}
		if f.UncompressedSize64 > 120<<20 {
			return errors.New("повреждённый архив: файл слишком велик")
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, 120<<20))
		r.Close()
		if e != nil {
			return e
		}
		files[name] = b
	}
	for k := range need {
		if len(files[k]) == 0 {
			return fmt.Errorf("в ZIP отсутствует %s", k)
		}
	}
	dir := filepath.Dir(a.enginePath())
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	// Пишем в безопасную временную директорию, затем переносим только нужные файлы.
	tmp, e := os.MkdirTemp(a.dir, "xray-install-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	for n, b := range files {
		if e = os.WriteFile(filepath.Join(tmp, n), b, 0700); e != nil {
			return e
		}
	}
	for n := range need {
		dst := filepath.Join(dir, n)
		src := filepath.Join(tmp, n)
		if e = os.Rename(src, dst); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) installArchiveFile(path string) error {
	if a.haveCore() {
		return nil
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return e
	}
	if stat.Size() > 65<<20 {
		return errors.New("архив слишком большой")
	}
	body, e := io.ReadAll(io.LimitReader(f, 65<<20))
	if e != nil {
		return e
	}
	return a.installOfficial(body)
}
func (a *App) ensureCore() error {
	if a.haveCore() {
		return nil
	}
	if runtime.GOOS != "windows" {
		return errors.New("Windows-версия необходима для установки")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	var errs []string
	for _, candidate := range []string{engineURL, engineMirrorURL} {
		body, e := download(ctx, candidate, 65<<20)
		if e != nil {
			errs = append(errs, e.Error())
			continue
		}
		if e = a.installOfficial(body); e == nil {
			return nil
		}
		errs = append(errs, e.Error())
	}
	// Ни одна загрузка не подходит, никакой случайный бинарный файл не исполняем.
	return fmt.Errorf("не удалось установить официальный Xray: %s. Используй «Скачать официальный ZIP» → «Установить из ZIP»", safeLog(strings.Join(errs, "; ")))
}
func (a *App) updateRUCIDRs() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, e := download(ctx, ipListURL, 2<<20)
	if e != nil {
		return e
	}
	p := filepath.Join(a.dir, "ru-cidrs.txt")
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	if len(readRUCIDRs(tmp)) < 100 {
		_ = os.Remove(tmp)
		return errors.New("слишком короткий список IP")
	}
	return os.Rename(tmp, p)
}
func checkCore(core, config string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "-test", "-c", config)
	cmd.Dir = filepath.Dir(core)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("проверка конфигурации Xray: %s", safeLog(string(out)))
	}
	return nil
}

// Сохраняем тип сетевой ошибки, но убираем ссылки с ключами и UUID.
var urlSecretRe = regexp.MustCompile(`(?i)(?:vless|trojan|vmess|https?|ss)://[^\s\"']+`)
var uuidSecretRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

func safeLog(s string) string {
	s = urlSecretRe.ReplaceAllString(s, "[URL скрыт]")
	s = uuidSecretRe.ReplaceAllString(s, "[UUID скрыт]")
	lines := strings.Split(s, "\n")
	out := []string{}
	for _, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "password=") || strings.Contains(low, "secret=") || strings.Contains(low, "authorization:") {
			continue
		}
		if len(l) > 500 {
			l = l[:500]
		}
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	v := strings.Join(out, "\n")
	if len(v) > 1400 {
		v = v[:1400]
	}
	if v == "" {
		return "причина отсутствует в журнале — смотри probe.log"
	}
	return v
}
