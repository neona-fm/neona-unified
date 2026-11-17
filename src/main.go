package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed web/index.html
var indexHTML string

// Запуск отдельного приложения. В Windows используется нативное окно,
// старый HTML-интерфейс оставлен в исходниках только для совместимости.
func main() {
	root, err := os.UserConfigDir()
	if err != nil {
		root = os.TempDir()
	}
	dir := filepath.Join(root, "NeonaOneVPN")
	if err = os.MkdirAll(dir, 0700); err != nil {
		panic(err)
	}
	// Загружаем старую проверенную конфигурацию только при первом старте.
	// Далее она хранится независимо и изменяется прямо в нашем едином окне.
	migrationErr := migrateProfile(dir, filepath.Join(root, "NeonaSplitVPN"))
	a := newApp(dir)
	if migrationErr != nil {
		a.note = "Перенос VPN 1.5: " + migrationErr.Error()
	}
	_ = a.readSource() // новая сборка читает прежнюю сохранённую подписку
	// Останавливаем только старый Python-наблюдатель, который мог
	// показывать модальные предупреждения и перезапускать соединения.
	// Не трогаем Xray, VPN-агент и tunnel-client.
	if n, e := stopLegacyPythonNotifier(); e != nil {
		a.note = "Старая служба уведомлений: " + e.Error()
	} else if n > 0 {
		a.note = "Отключена старая служба уведомлений; работающие соединения сохранены"
	}
	launchUI(a)
}
