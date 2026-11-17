//go:build windows

package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Раздел 7. Компактное нативное окно Windows с отрисованными карточками,
// без браузера, без локального веб-сервера и без дополнительных UI-библиотек.
const (
	esPassword        = 0x0020
	emSetPasswordChar = 0x00CC
	wmAppStopped      = 0x8004
	idSaveMCP         = 119
	idShowKeys        = 120
	idCopyLog         = 121
	idPasteVPN        = 122
	idCheckMCP        = 123
	wsOverlapped      = 0x00CF0000
	wsVisible         = 0x10000000
	wsChild           = 0x40000000
	wsTabStop         = 0x00010000
	wsBorder          = 0x00800000
	wsVScroll         = 0x00200000
	esAutoHScroll     = 0x0080
	cbDropDownList    = 0x0003
	ssLeft            = 0
	bsOwnerDraw       = 0x0000000B
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmSize            = 0x0005
	wmGetMinMaxInfo   = 0x0024
	wmCommand         = 0x0111
	wmTimer           = 0x0113
	wmSetFont         = 0x0030
	wmAppResult       = 0x8001
	wmDrawItem        = 0x002B
	wmCtlColorStatic  = 0x0138
	wmEraseBkgnd      = 0x0014
	wmPaint           = 0x000F
	wmCtlColorEdit    = 0x0133
	wmCtlColorList    = 0x0134
	cbResetContent    = 0x014B
	cbAddString       = 0x0143
	cbSetCurSel       = 0x014E
	cbGetCurSel       = 0x0147
	cbnSelChange      = 1
	swShow            = 5
	idInstall         = 101
	idImport          = 102
	idRefresh         = 103
	idIP              = 104
	idConnect         = 105
	idDisconnect      = 106
	idConfirm         = 107
	idFolder          = 108
	idLogs            = 109
	idExit            = 110
	idServer          = 111
	idInstallLocal    = 112
	idOfficial        = 113
)

var (
	user32                            = syscall.NewLazyDLL("user32.dll")
	kernel32Native                    = syscall.NewLazyDLL("kernel32.dll")
	gdi32                             = syscall.NewLazyDLL("gdi32.dll")
	comdlg32                          = syscall.NewLazyDLL("comdlg32.dll")
	fnRegisterClass                   = user32.NewProc("RegisterClassExW")
	fnCreateWindow                    = user32.NewProc("CreateWindowExW")
	fnDefWindowProc                   = user32.NewProc("DefWindowProcW")
	fnShowWindow                      = user32.NewProc("ShowWindow")
	fnUpdateWindow                    = user32.NewProc("UpdateWindow")
	fnGetMessage                      = user32.NewProc("GetMessageW")
	fnTranslateMessage                = user32.NewProc("TranslateMessage")
	fnDispatchMessage                 = user32.NewProc("DispatchMessageW")
	fnPostQuitMessage                 = user32.NewProc("PostQuitMessage")
	fnPostMessage                     = user32.NewProc("PostMessageW")
	fnDestroyWindow                   = user32.NewProc("DestroyWindow")
	fnSetWindowText                   = user32.NewProc("SetWindowTextW")
	fnGetWindowText                   = user32.NewProc("GetWindowTextW")
	fnGetWindowTextLength             = user32.NewProc("GetWindowTextLengthW")
	fnSendMessage                     = user32.NewProc("SendMessageW")
	fnEnableWindow                    = user32.NewProc("EnableWindow")
	fnSetTimer                        = user32.NewProc("SetTimer")
	fnMessageBox                      = user32.NewProc("MessageBoxW")
	fnLoadCursor                      = user32.NewProc("LoadCursorW")
	fnGetWindowRect                   = user32.NewProc("GetWindowRect")
	fnGetSystemMetrics                = user32.NewProc("GetSystemMetrics")
	fnSetWindowPos                    = user32.NewProc("SetWindowPos")
	fnGetClientRect                   = user32.NewProc("GetClientRect")
	fnBeginPaint                      = user32.NewProc("BeginPaint")
	fnEndPaint                        = user32.NewProc("EndPaint")
	fnInvalidateRect                  = user32.NewProc("InvalidateRect")
	fnDrawText                        = user32.NewProc("DrawTextW")
	fnGetModuleHandle                 = kernel32Native.NewProc("GetModuleHandleW")
	fnCreateFont                      = gdi32.NewProc("CreateFontW")
	fnCreateSolidBrush                = gdi32.NewProc("CreateSolidBrush")
	fnSelectObject                    = gdi32.NewProc("SelectObject")
	fnDeleteObject                    = gdi32.NewProc("DeleteObject")
	fnFillRect                        = user32.NewProc("FillRect")
	fnRoundRect                       = gdi32.NewProc("RoundRect")
	fnSetTextColor                    = gdi32.NewProc("SetTextColor")
	fnSetBkMode                       = gdi32.NewProc("SetBkMode")
	fnGetOpenFileName                 = comdlg32.NewProc("GetOpenFileNameW")
	fnGetStockObject                  = gdi32.NewProc("GetStockObject")
	mainUI                            *nativeUI
	brushHeader, brushCard, brushBack uintptr
)

type wndClassEx struct {
	Size, Style                        uint32
	WindowProc                         uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	IconSm                             uintptr
}
type point struct{ X, Y int32 }
type msg struct {
	Hwnd           uintptr
	Message        uint32
	Wparam, Lparam uintptr
	Time           uint32
	Pt             point
	Lprivate       uint32
}
type rect struct{ Left, Top, Right, Bottom int32 }
type paintStruct struct {
	HDC                uintptr
	Erase              int32
	Paint              rect
	Restore, IncUpdate int32
	Reserved           [32]byte
}
type drawItem struct {
	CtlType, CtlID, ItemID, ItemAction, ItemState uint32
	HwndItem, HDC                                 uintptr
	RcItem                                        rect
	ItemData                                      uintptr
}
type openFileName struct {
	Size                       uint32
	Owner, Instance            uintptr
	Filter, CustomFilter       *uint16
	MaxCustFilter, FilterIndex uint32
	File                       *uint16
	MaxFile                    uint32
	FileTitle                  *uint16
	MaxFileTitle               uint32
	InitialDir, Title          *uint16
	Flags                      uint32
	FileOffset, FileExtension  uint16
	DefExt                     *uint16
	CustData, Hook             uintptr
	TemplateName               *uint16
	Reserved                   uintptr
	DWReserved, FlagsEx        uint32
}
type nativeUI struct {
	app                                     *App
	unified                                 *unifiedController
	keysShown                               bool
	hwnd                                    uintptr
	controls                                map[int]uintptr
	fields                                  map[string]uintptr
	font, fontTitle, fontHeading, fontSmall uintptr
	busy                                    bool
	busyAction, resultMsg                   string
	resultOk                                bool
	nodesKey                                string
	settingCombo                            bool
	layouts                                 map[uintptr]rect
}

func u16(s string) *uint16          { return syscall.StringToUTF16Ptr(s) }
func rgb(r, g, b byte) uintptr      { return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16 }
func createSolid(c uintptr) uintptr { v, _, _ := fnCreateSolidBrush.Call(c); return v }
func cText(hwnd uintptr, s string)  { fnSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(u16(s)))) }
func setEnabled(hwnd uintptr, allow bool) {
	var v uintptr
	if allow {
		v = 1
	}
	fnEnableWindow.Call(hwnd, v)
}
func send(hwnd uintptr, m uint32, w, l uintptr) uintptr {
	r, _, _ := fnSendMessage.Call(hwnd, uintptr(m), w, l)
	return r
}
func createW(parent uintptr, class, title string, x, y, w, h int32, style uint32, id uintptr) uintptr {
	v, _, _ := fnCreateWindow.Call(0, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(title))), uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, 0, 0)
	return v
}

// Все элементы запоминают исходные координаты и масштабируются при изменении ширины окна.
func (ui *nativeUI) remember(hwnd uintptr, x, y, w, h int32) {
	if ui.layouts != nil && hwnd != 0 {
		ui.layouts[hwnd] = rect{x, y, x + w, y + h}
	}
}
func (ui *nativeUI) mapX(x, clientW int32) int32 {
	if clientW < 850 {
		clientW = 850
	}
	usable := clientW - 65
	leftW := int32(math.Round(float64(usable) * 602.0 / 1075.0))
	rightX := int32(21) + leftW + 17
	rightW := clientW - 27 - rightX
	switch {
	case x <= 623:
		return 21 + int32(math.Round(float64(x-21)*float64(leftW)/602.0))
	case x >= 640:
		return rightX + int32(math.Round(float64(x-640)*float64(rightW)/473.0))
	default:
		return 21 + leftW + int32(math.Round(float64(x-623)*17.0/17.0))
	}
}
func (ui *nativeUI) widthNow() (int32, int32) {
	if ui.hwnd == 0 {
		return 1140, 850
	}
	var r rect
	if v, _, _ := fnGetClientRect.Call(ui.hwnd, uintptr(unsafe.Pointer(&r))); v == 0 {
		return 1140, 850
	}
	return r.Right - r.Left, r.Bottom - r.Top
}
func (ui *nativeUI) layoutControls() {
	cw, _ := ui.widthNow()
	for hwnd, b := range ui.layouts {
		left := ui.mapX(b.Left, cw)
		right := ui.mapX(b.Right, cw)
		ww := right - left
		if ww < 20 {
			ww = 20
		}
		// SWP_NOZORDER | SWP_NOACTIVATE
		fnSetWindowPos.Call(hwnd, 0, uintptr(left), uintptr(b.Top), uintptr(ww), uintptr(b.Bottom-b.Top), 0x0004|0x0010)
	}
}
func (ui *nativeUI) field(name, class, title string, x, y, w, h int32, style uint32, font uintptr) uintptr {
	wnd := createW(ui.hwnd, class, title, x, y, w, h, wsChild|wsVisible|style, 0)
	ui.fields[name] = wnd
	ui.remember(wnd, x, y, w, h)
	if font == 0 {
		font = ui.font
	}
	send(wnd, wmSetFont, font, 1)
	return wnd
}
func (ui *nativeUI) label(name, title string, x, y, w, h int32, font uintptr) uintptr {
	return ui.field(name, "STATIC", title, x, y, w, h, ssLeft, font)
}
func (ui *nativeUI) button(id int, title string, x, y, w, h int32) uintptr {
	wnd := createW(ui.hwnd, "BUTTON", title, x, y, w, h, wsChild|wsVisible|wsTabStop|bsOwnerDraw, uintptr(id))
	ui.controls[id] = wnd
	ui.remember(wnd, x, y, w, h)
	send(wnd, wmSetFont, ui.font, 1)
	return wnd
}
func (ui *nativeUI) get(h uintptr) string {
	length, _, _ := fnGetWindowTextLength.Call(h)
	if length > 16384 {
		length = 16384
	}
	buf := make([]uint16, int(length)+1)
	fnGetWindowText.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}
func (ui *nativeUI) note(s string, ok bool) {
	ui.resultMsg = s
	ui.resultOk = ok
	cText(ui.fields["feedback"], s)
}
func (ui *nativeUI) run(label string, f func() error) {
	if ui.busy {
		return
	}
	ui.busy = true
	ui.busyAction = label
	ui.note("Выполняется: "+label+"…", true)
	ui.refresh()
	go func() {
		err := f()
		if err != nil {
			ui.resultMsg = "Ошибка: " + safeLog(err.Error())
			ui.resultOk = false
		} else {
			if label == "импорт ссылки" {
				ui.app.mu.Lock()
				n := len(ui.app.nodes)
				ui.app.mu.Unlock()
				ui.resultMsg = fmt.Sprintf("Готово: принято серверов — %d", n)
			} else {
				ui.resultMsg = "Готово: " + label
			}
			ui.resultOk = true
		}
		fnPostMessage.Call(ui.hwnd, wmAppResult, 0, 0)
	}()
}
func browseZip(owner uintptr) string {
	b := make([]uint16, 4096)
	filter := []uint16{'Z', 'I', 'P', ' ', '(', '*', '.', 'z', 'i', 'p', ')', 0, '*', '.', 'z', 'i', 'p', 0, 'В', 'с', 'е', ' ', 'ф', 'а', 'й', 'л', 'ы', 0, '*', '.', '*', 0, 0}
	ofn := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: owner, Filter: &filter[0], File: &b[0], MaxFile: uint32(len(b)), Title: u16("Выбери официальный Xray-windows-64.zip"), Flags: 0x800 | 0x1000}
	r, _, _ := fnGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(b)
}
func (ui *nativeUI) command(id int) {
	switch id {
	case idInstall:
		ui.run("установка Xray-core", func() error { return ui.app.ensureCore() })
	case idInstallLocal:
		if path := browseZip(ui.hwnd); path != "" {
			ui.run("установка из ZIP", func() error { return ui.app.installArchiveFile(path) })
		}
	case idOfficial:
		openBrowser(engineURL)
	case idPasteVPN:
		value, err := readClipboardText()
		if err != nil {
			ui.note("Не удалось вставить: "+safeLog(err.Error()), false)
			return
		}
		cText(ui.fields["input"], strings.TrimSpace(value))
		ui.note("Ссылка вставлена. Нажми 'Сохранить VPN'.", true)
	case idImport:
		link := strings.TrimSpace(ui.get(ui.fields["input"]))
		if link == "" {
			ui.note("Вставь ссылку подписки или VLESS-сервера.", false)
			return
		}
		ui.run("импорт ссылки", func() error { _, e := ui.app.importLink(link); return e })
	case idRefresh:
		ui.run("обновление подписки", func() error { return ui.app.updateNodes() })
	case idIP:
		ui.run("обновление RU IP", func() error { return ui.app.updateRUCIDRs() })
	case idConnect:
		ui.run("последовательный запуск", func() error { return ui.unified.startAll() })
	case idDisconnect:
		ui.note("Останавливаю VPN и MCP...", true)
		go func() { ui.unified.stopAll(); fnPostMessage.Call(ui.hwnd, wmAppStopped, 0, 0) }()
	case idConfirm:
		ui.run("проверка системного IP", func() error { return ui.app.confirm() })
	case idFolder:
		_ = exec.Command("explorer.exe", ui.app.dir).Start()
	case idLogs:
		// Показываем свежий журнал: preflight до TUN или engine после TUN.
		engine := ui.app.dir + "\\engine.log"
		probe := ui.app.dir + "\\probe.log"
		path := engine
		eInfo, eErr := os.Stat(engine)
		pInfo, pErr := os.Stat(probe)
		if pErr == nil && (eErr != nil || pInfo.ModTime().After(eInfo.ModTime())) {
			path = probe
		}
		if _, e := os.Stat(path); e != nil {
			ui.note("Журнал появится после первой попытки подключения.", false)
			return
		}
		_ = exec.Command("notepad.exe", path).Start()
	case idSaveMCP:
		api := strings.TrimSpace(ui.get(ui.fields["mcpApi"]))
		tok := strings.TrimSpace(ui.get(ui.fields["mcpChrome"]))
		ui.run("сохранение ключей MCP", func() error { return ui.unified.mcp.saveSecrets(api, tok) })
	case idShowKeys:
		ui.keysShown = !ui.keysShown
		var char uintptr = uintptr('●')
		if ui.keysShown {
			char = 0
		}
		send(ui.fields["mcpApi"], emSetPasswordChar, char, 0)
		send(ui.fields["mcpChrome"], emSetPasswordChar, char, 0)
		fnInvalidateRect.Call(ui.fields["mcpApi"], 0, 1)
		fnInvalidateRect.Call(ui.fields["mcpChrome"], 0, 1)
		if ui.keysShown {
			cText(ui.controls[idShowKeys], "Скрыть ключи")
		} else {
			cText(ui.controls[idShowKeys], "Показать ключи")
		}
	case idCheckMCP:
		ui.run("проверка MCP по запросу", func() error { ui.unified.mcp.poll(); return nil })
	case idCopyLog:
		if err := copyDiagnostics(ui.unified); err != nil {
			ui.note("Ошибка копирования: "+safeLog(err.Error()), false)
		} else {
			ui.note("Диагностика скопирована", true)
		}
	case idExit:
		fnDestroyWindow.Call(ui.hwnd)
	case idServer:
		if ui.settingCombo || ui.busy {
			return
		}
		n := send(ui.controls[idServer], cbGetCurSel, 0, 0)
		ui.run("выбор сервера", func() error {
			ui.app.mu.Lock()
			defer ui.app.mu.Unlock()
			if ui.app.running {
				return fmt.Errorf("сначала отключи VPN")
			}
			if int(n) < 0 || int(n) >= len(ui.app.nodes) {
				return fmt.Errorf("выбери сервер")
			}
			if e := ui.app.saveProfile(ui.app.source, ui.app.nodes, int(n)); e != nil {
				return e
			}
			ui.app.selected = int(n)
			return nil
		})
	}
}
func (ui *nativeUI) refresh() {
	if ui.hwnd == 0 {
		return
	}
	s := ui.app.statusJSON()
	running := s["running"].(bool)
	core := s["core"].(bool)
	saved := s["saved"].(bool)
	nodes := s["nodes"].([]map[string]string)
	ru := s["ruNetworks"].(int)
	if core {
		cText(ui.fields["core"], "✓ Xray-core "+engineVersion+" установлен")
	} else {
		cText(ui.fields["core"], "○ Движок пока не установлен")
	}
	if saved {
		cText(ui.fields["subscription"], fmt.Sprintf("✓ Подписка сохранена · %d серверов", len(nodes)))
	} else {
		cText(ui.fields["subscription"], "○ Добавь ссылку — серверы появятся ниже")
	}
	if ru >= 100 {
		cText(ui.fields["ru"], fmt.Sprintf("✓ IP России: %d сетей", ru))
	} else {
		cText(ui.fields["ru"], "✓ RU-домены и GeoIP:ru включены")
	}
	status := s["status"].(string)
	cText(ui.fields["status"], status)
	if ui.unified != nil {
		cText(ui.fields["windowsMCP"], ui.unified.describe(tunnelWindows))
		cText(ui.fields["chromeMCP"], ui.unified.describe(tunnelChrome))
	}
	note, _ := s["note"].(string)
	cText(ui.fields["info"], note)
	var key strings.Builder
	for _, n := range nodes {
		key.WriteString(n["index"])
		key.WriteByte('|')
		key.WriteString(n["name"])
		key.WriteByte(';')
	}
	if key.String() != ui.nodesKey {
		ui.settingCombo = true
		combo := ui.controls[idServer]
		send(combo, cbResetContent, 0, 0)
		for _, n := range nodes {
			label := n["name"] + "  ·  " + strings.ToUpper(n["protocol"])
			send(combo, cbAddString, 0, uintptr(unsafe.Pointer(u16(label))))
		}
		ui.nodesKey = key.String()
		ui.settingCombo = false
	}
	if len(nodes) > 0 {
		ui.settingCombo = true
		send(ui.controls[idServer], cbSetCurSel, uintptr(s["selected"].(int)), 0)
		ui.settingCombo = false
	}
	for _, id := range []int{idInstall, idInstallLocal, idOfficial, idImport, idRefresh, idIP, idConnect, idDisconnect, idConfirm, idServer, idSaveMCP, idShowKeys, idCopyLog, idPasteVPN, idCheckMCP} {
		enabled := !ui.busy || id == idDisconnect
		switch id {
		case idImport, idInstall, idInstallLocal, idIP:
			enabled = enabled && !running
		case idRefresh, idServer:
			enabled = enabled && saved && !running
		case idConnect:
			enabled = enabled && core && len(nodes) > 0 && !ui.unified.isActive()
		case idDisconnect:
			enabled = running || ui.unified.isActive()
		case idConfirm:
			enabled = enabled && running
		}
		setEnabled(ui.controls[id], enabled)
	}
}
func fill(hdc uintptr, r rect, color uintptr) {
	brush := createSolid(color)
	fnFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), brush)
	fnDeleteObject.Call(brush)
}
func rounded(hdc uintptr, x, y, w, h, rad int32, color uintptr) {
	brush := createSolid(color)
	old, _, _ := fnSelectObject.Call(hdc, brush)
	nullPen, _, _ := fnGetStockObject.Call(8)
	oldPen, _, _ := fnSelectObject.Call(hdc, nullPen)
	// с заливкой прямоугольника с лёгким скруглением (обводка системным пером)
	fnRoundRect.Call(hdc, uintptr(x), uintptr(y), uintptr(x+w), uintptr(y+h), uintptr(rad), uintptr(rad))
	fnSelectObject.Call(hdc, oldPen)
	fnSelectObject.Call(hdc, old)
	fnDeleteObject.Call(brush)
}
func (ui *nativeUI) paint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := fnBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	cw, ch := ui.widthNow()
	fill(hdc, rect{0, 0, cw, ch}, rgb(244, 247, 252))
	fill(hdc, rect{0, 0, cw, 141}, rgb(28, 38, 69))
	rounded(hdc, ui.mapX(21, cw), 159, ui.mapX(623, cw)-ui.mapX(21, cw), 416, 16, rgb(255, 255, 255))
	rounded(hdc, ui.mapX(640, cw), 159, ui.mapX(1113, cw)-ui.mapX(640, cw), 547, 16, rgb(255, 255, 255))
	rounded(hdc, ui.mapX(21, cw), 710, ui.mapX(1113, cw)-ui.mapX(21, cw), 136, 16, rgb(255, 255, 255))
	fnEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
}
func (ui *nativeUI) drawButton(ptr uintptr) {
	di := (*drawItem)(unsafe.Pointer(ptr))
	id := int(di.CtlID)
	enabled := di.ItemState&0x4 == 0
	pressed := di.ItemState&1 != 0
	c := rgb(235, 240, 250)
	fg := rgb(30, 45, 78)
	primary := id == idConnect || id == idImport || id == idConfirm || id == idSaveMCP
	destructive := id == idDisconnect
	if primary {
		c = rgb(82, 92, 207)
		fg = rgb(255, 255, 255)
	}
	if destructive {
		c = rgb(255, 235, 238)
		fg = rgb(173, 49, 68)
	}
	if !enabled {
		c = rgb(232, 236, 243)
		fg = rgb(153, 162, 177)
	}
	if enabled && pressed {
		if primary {
			c = rgb(65, 75, 178)
		} else {
			c = rgb(215, 222, 236)
		}
	}
	rc := di.RcItem
	rounded(di.HDC, rc.Left+1, rc.Top+1, rc.Right-rc.Left-2, rc.Bottom-rc.Top-2, 12, c)
	fnSetTextColor.Call(di.HDC, fg)
	fnSetBkMode.Call(di.HDC, 1)
	old, _, _ := fnSelectObject.Call(di.HDC, ui.font)
	title := ui.get(di.HwndItem)
	str := u16(title)
	fnDrawText.Call(di.HDC, uintptr(unsafe.Pointer(str)), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), 0x00000001|0x00000004|0x00000020)
	fnSelectObject.Call(di.HDC, old)
}
func (ui *nativeUI) colorStatic(hdc, hwnd uintptr) uintptr {
	col := rgb(48, 61, 85)
	if hwnd == ui.fields["title"] || hwnd == ui.fields["subtitle"] || hwnd == ui.fields["tagline"] {
		col = rgb(255, 255, 255)
	}
	if hwnd == ui.fields["feedback"] {
		if ui.resultOk {
			col = rgb(33, 122, 89)
		} else {
			col = rgb(192, 52, 66)
		}
	}
	if hwnd == ui.fields["core"] || hwnd == ui.fields["subscription"] || hwnd == ui.fields["ru"] {
		col = rgb(58, 99, 121)
	}
	if hwnd == ui.fields["status"] {
		if ui.app.statusJSON()["running"].(bool) {
			col = rgb(42, 127, 100)
		} else {
			col = rgb(70, 80, 115)
		}
	}
	fnSetTextColor.Call(hdc, col)
	fnSetBkMode.Call(hdc, 1)
	if hwnd == ui.fields["title"] || hwnd == ui.fields["subtitle"] || hwnd == ui.fields["tagline"] {
		return brushHeader
	}
	if hwnd == ui.fields["feedback"] {
		return brushBack
	}
	return brushCard
}
func proc(hwnd uintptr, message uint32, w, l uintptr) uintptr {
	ui := mainUI
	if ui != nil {
		switch message {
		case wmGetMinMaxInfo:
			// Не даём уменьшить окно так, чтобы нижние кнопки стали недоступны.
			if l != 0 {
				track := (*[10]int32)(unsafe.Pointer(l))
				track[6], track[7] = 1040, 885
			}
			return 0
		case wmSize:
			ui.layoutControls()
			fnInvalidateRect.Call(hwnd, 0, 1)
			return 0
		case wmEraseBkgnd:
			return 1
		case wmPaint:
			ui.paint(hwnd)
			return 0
		case wmCtlColorStatic:
			return ui.colorStatic(w, l)
		case wmDrawItem:
			ui.drawButton(l)
			return 1
		case wmCommand:
			id := int(w & 0xffff)
			notification := uint16((w >> 16) & 0xffff)
			if id == idServer {
				if notification == cbnSelChange {
					ui.command(id)
				}
			} else if _, ok := ui.controls[id]; ok {
				ui.command(id)
			}
			return 0
		case wmAppStopped:
			ui.note("Все соединения остановлены", true)
			ui.refresh()
			return 0
		case wmAppResult:
			ui.busy = false
			ui.note(ui.resultMsg, ui.resultOk)

			ui.refresh()
			return 0
		case wmTimer:
			ui.refresh()
			return 0
		case wmClose:
			ui.unified.close()
			fnDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			fnPostQuitMessage.Call(0)
			return 0
		}
	}
	val, _, _ := fnDefWindowProc.Call(hwnd, uintptr(message), w, l)
	return val
}
func newFont(height, weight int32) uintptr {
	f, _, _ := fnCreateFont.Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 0, 0, uintptr(unsafe.Pointer(u16("Segoe UI"))))
	return f
}
func showNativeUI(a *App) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ui := &nativeUI{app: a, unified: newUnifiedController(a), controls: map[int]uintptr{}, fields: map[string]uintptr{}, layouts: map[uintptr]rect{}}
	mainUI = ui
	inst, _, _ := fnGetModuleHandle.Call(0)
	cursor, _, _ := fnLoadCursor.Call(0, 32512)
	cname := u16("NeonaUnifiedNativeV2")
	wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WindowProc: syscall.NewCallback(proc), Instance: inst, Cursor: cursor, ClassName: cname}
	if r, _, e := fnRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		fnMessageBox.Call(0, uintptr(unsafe.Pointer(u16("Не удалось создать окно: "+e.Error()))), uintptr(unsafe.Pointer(u16("Neona Split VPN"))), 0)
		return
	}
	brushHeader = createSolid(rgb(28, 38, 69))
	brushCard = createSolid(rgb(255, 255, 255))
	brushBack = createSolid(rgb(244, 247, 252))
	ui.font = newFont(-18, 400)
	ui.fontTitle = newFont(-35, 650)
	ui.fontHeading = newFont(-21, 600)
	ui.fontSmall = newFont(-16, 400)
	// Обычное окно Windows: можно растянуть и развернуть на весь экран.
	style := uint32(wsOverlapped)
	sx, _, _ := fnGetSystemMetrics.Call(0)
	sy, _, _ := fnGetSystemMetrics.Call(1)
	x := int32((int(sx) - 1140) / 2)
	y := int32((int(sy) - 900) / 2)
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	hwnd := createW(0, "NeonaUnifiedNativeV2", "Neona Unified — VPN + Windows/Chrome MCP", x, y, 1140, 900, style, 0)
	if hwnd == 0 {
		return
	}
	ui.hwnd = hwnd
	ui.label("title", "Neona Unified", 33, 25, 700, 47, ui.fontTitle)
	ui.label("subtitle", "Один запуск VPN и туннелей · без фоновых переподключений", 35, 79, 740, 27, ui.font)
	ui.label("tagline", "Оригинальная маршрутизация VPN 1.5 · MCP Manager 0.3.5", 35, 111, 845, 23, ui.fontSmall)
	ui.label("subscriptionHeading", "Подписка и сервер", 47, 181, 540, 32, ui.fontHeading)
	ui.label("inputLabel", "Вставь ссылку VLESS или адрес подписки", 47, 223, 531, 26, ui.fontSmall)
	ui.field("input", "EDIT", "", 47, 253, 548, 36, wsBorder|wsTabStop|esAutoHScroll, ui.font)
	ui.button(idImport, "Сохранить VPN", 47, 308, 174, 42)
	ui.button(idRefresh, "Обновить подписку", 232, 308, 190, 42)
	ui.button(idPasteVPN, "Вставить ссылку", 432, 308, 164, 42)
	ui.label("subscription", "Проверяем…", 47, 363, 540, 28, ui.fontSmall)
	ui.label("serverLabel", "Выбранный сервер", 47, 405, 530, 24, ui.fontSmall)
	combo := createW(hwnd, "COMBOBOX", "", 47, 436, 548, 240, wsChild|wsVisible|cbDropDownList|wsTabStop|wsVScroll, idServer)
	ui.controls[idServer] = combo
	ui.remember(combo, 47, 436, 548, 240)
	send(combo, wmSetFont, ui.font, 1)
	ui.label("routeTip", "Маршрут: .ru / .рф / российские IP — напрямую", 47, 500, 540, 28, ui.fontSmall)
	ui.label("engineHeading", "MCP-туннели", 663, 181, 425, 32, ui.fontHeading)
	ui.label("windowsMCP", "Windows MCP: ...", 662, 224, 425, 53, ui.fontSmall)
	ui.label("chromeMCP", "Chrome MCP: ...", 662, 283, 425, 53, ui.fontSmall)
	ui.label("apiKeyTitle", "Ключ OpenAI для MCP:", 662, 340, 415, 27, ui.fontSmall)
	ui.field("mcpApi", "EDIT", "", 662, 371, 426, 35, wsBorder|wsTabStop|esAutoHScroll|esPassword, ui.font)
	ui.label("chromeKeyTitle", "Токен расширения Chrome:", 662, 414, 419, 28, ui.fontSmall)
	ui.field("mcpChrome", "EDIT", "", 662, 448, 426, 35, wsBorder|wsTabStop|esAutoHScroll|esPassword, ui.font)
	ui.button(idSaveMCP, "Сохранить ключи", 662, 493, 206, 39)
	ui.button(idShowKeys, "Показать ключи", 882, 493, 207, 39)
	ui.label("mcpHint", "Ключи хранятся в прежнем DPAPI-хранилище", 662, 540, 430, 40, ui.fontSmall)
	ui.label("mcpLogsTitle", "Проверка MCP — только вручную", 662, 585, 430, 30, ui.fontSmall)
	ui.button(idCheckMCP, "Проверить MCP", 662, 620, 200, 44)
	ui.button(idCopyLog, "Скопировать лог", 874, 620, 214, 44)
	// Движок VPN использует существующий Xray в профиле 1.5.
	ui.label("core", "Проверяем Xray…", 48, 529, 540, 24, ui.fontSmall)
	ui.label("ru", "Проверяем RU…", 48, 558, 540, 24, ui.fontSmall)
	ui.button(idInstall, "Установить Xray", 47, 595, 172, 36)
	ui.button(idInstallLocal, "Xray из ZIP", 228, 595, 158, 36)
	ui.button(idOfficial, "Скачать Xray", 396, 595, 180, 36)
	ui.button(idIP, "Обновить RU IP", 47, 645, 169, 36)
	ui.label("statusHeading", "Общий запуск", 47, 725, 440, 27, ui.fontHeading)
	ui.label("status", "Отключено", 47, 755, 575, 48, ui.fontSmall)
	ui.button(idConnect, "▶ Запустить всё", 655, 725, 206, 45)
	ui.button(idDisconnect, "■ Остановить всё", 873, 725, 211, 45)
	ui.button(idConfirm, "Проверить VPN", 658, 779, 205, 35)
	ui.label("info", "", 47, 810, 550, 25, ui.fontSmall)
	ui.label("feedback", "", 47, 690, 1042, 25, ui.fontSmall)
	ui.button(idFolder, "Папка VPN", 232, 645, 164, 36)
	ui.button(idLogs, "Журнал VPN", 407, 645, 171, 36)
	// Загружаем сохранённую VPN-подписку и MCP-ключи в то же окно.
	a.mu.Lock()
	cText(ui.fields["input"], a.source)
	a.mu.Unlock()
	if api, chrome, err := ui.unified.mcp.getSavedSecrets(); err == nil {
		cText(ui.fields["mcpApi"], api)
		cText(ui.fields["mcpChrome"], chrome)
	} else {
		ui.note("Ключи MCP: "+safeLog(err.Error()), false)
	}
	ui.layoutControls()
	ui.refresh()
	// Один снимок текущих MCP при открытии; фоновых опросов больше нет.
	go ui.unified.mcp.poll()
	fnShowWindow.Call(hwnd, swShow)
	fnUpdateWindow.Call(hwnd)
	fnSetTimer.Call(hwnd, 1, 1200, 0)
	var m msg
	for {
		r, _, _ := fnGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		fnTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		fnDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}
