//go:build windows

package system

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func sysRoot() string {
	if s := os.Getenv("SystemRoot"); s != "" {
		return s
	}
	return `C:\Windows`
}

// scheduledTasks %SystemRoot%\System32\Tasks dagi vazifalarni o'qiydi.
func scheduledTasks() []Autorun {
	root := filepath.Join(sysRoot(), "System32", "Tasks")
	var out []Autorun
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || len(data) > 1<<20 {
			return nil
		}
		cmds, enabled := TaskActions(data)
		rel, _ := filepath.Rel(root, p)
		name := `\` + rel
		for _, c := range cmds {
			out = append(out, Autorun{
				Kind: AutorunTask, Location: "Task Scheduler", Name: name, Command: c, Paths: CommandPaths(c),
				Microsoft: strings.HasPrefix(strings.ToLower(name), `\microsoft\`), Disabled: !enabled, key: name,
			})
		}
		return nil
	})
	return out
}

// services avtomatik ishga tushadigan xizmatlar va drayverlar.
func services() []Autorun {
	const base = `SYSTEM\CurrentControlSet\Services`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []Autorun
	for _, n := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		start, _, err1 := sk.GetIntegerValue("Start")
		img, _, err2 := sk.GetStringValue("ImagePath")
		sk.Close()
		if err1 != nil || err2 != nil || img == "" || start > 2 {
			continue
		}
		img = ExpandPercent(img)
		var paths []string
		if strings.HasPrefix(strings.ToLower(img), `\`) || strings.HasPrefix(strings.ToLower(img), "system32") {
			paths = []string{NormalizeDriverPath(img, sysRoot())}
		} else {
			paths = CommandPaths(img)
		}
		if pk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+n+`\Parameters`, registry.QUERY_VALUE); err == nil {
			if dll, _, err := pk.GetStringValue("ServiceDll"); err == nil && dll != "" {
				paths = append(paths, ExpandPercent(dll))
			}
			pk.Close()
		}
		lowImg := strings.ToLower(img)
		ms := strings.Contains(lowImg, `\windows\`) || strings.Contains(lowImg, `systemroot`) || strings.HasPrefix(lowImg, "system32")
		out = append(out, Autorun{Kind: AutorunService, Location: `HKLM\` + base, Name: n, Command: img, Paths: paths, Microsoft: ms, root: uintptr(registry.LOCAL_MACHINE), key: base + `\` + n})
	}
	return out
}

const ifeoKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

// ifeo "Debugger" qiymati orqali dasturlarni almashtirish.
func ifeo() []Autorun {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeoKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []Autorun
	for _, n := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeoKey+`\`+n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dbg, _, err := sk.GetStringValue("Debugger")
		sk.Close()
		if err != nil || dbg == "" {
			continue
		}
		out = append(out, Autorun{Kind: AutorunIFEO, Location: `HKLM\` + ifeoKey + `\` + n, Name: n, Command: dbg, Paths: CommandPaths(dbg), root: uintptr(registry.LOCAL_MACHINE), key: ifeoKey + `\` + n})
	}
	return out
}

// appInit AppInit_DLLs — har bir GUI dasturga yuklanadigan DLL'lar.
func appInit() []Autorun {
	var out []Autorun
	for _, key := range []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue("AppInit_DLLs")
		load, _, _ := k.GetIntegerValue("LoadAppInit_DLLs")
		k.Close()
		if err != nil || strings.TrimSpace(v) == "" || load == 0 {
			continue
		}
		var paths []string
		for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			paths = append(paths, ExpandPercent(p))
		}
		out = append(out, Autorun{Kind: AutorunWinlogon, Location: `HKLM\` + key, Name: "AppInit_DLLs", Command: v, Paths: paths, Default: "", root: uintptr(registry.LOCAL_MACHINE), key: key})
	}
	return out
}

// removeExtra yangi turdagi yozuvlarni o'chiradi.
func removeExtra(a Autorun) error {
	switch a.Kind {
	case AutorunTask:
		out, err := exec.Command("schtasks.exe", "/Delete", "/TN", a.key, "/F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case AutorunService:
		_ = exec.Command("sc.exe", "stop", a.Name).Run()
		k, err := registry.OpenKey(registry.Key(a.root), a.key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetDWordValue("Start", 4) // o'chirib qo'yilgan
	case AutorunIFEO:
		k, err := registry.OpenKey(registry.Key(a.root), a.key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.DeleteValue("Debugger")
	}
	return errors.New("noma'lum yozuv turi")
}

// VerifySignature faylda haqiqiy Authenticode raqamli imzosi bormi (WinVerifyTrust).
func VerifySignature(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		ProvFlags:        windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: p,
		}),
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return err == nil
}

// ProcessModules jarayonga yuklangan DLL'lar yo'llari.
func ProcessModules(pid uint32) []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var out []string
	for err = windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		out = append(out, windows.UTF16ToString(me.ExePath[:]))
	}
	return out
}

// HostsPath hosts fayli yo'li.
func HostsPath() string { return filepath.Join(sysRoot(), "System32", "drivers", "etc", "hosts") }

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	procMessageBox = user32.NewProc("MessageBoxW")
	procShowWindow = user32.NewProc("ShowWindow")
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsole = kernel32.NewProc("GetConsoleWindow")
)

// HideConsole konsol oynasini yashiradi (fon rejimi uchun).
func HideConsole() {
	if h, _, _ := procGetConsole.Call(); h != 0 {
		procShowWindow.Call(h, 0) // SW_HIDE
	}
}

// Notify foydalanuvchiga ogohlantirish oynasini ko'rsatadi (bloklamaydi).
func Notify(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	go procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x30|0x40000|0x10000) // MB_ICONWARNING|MB_TOPMOST|MB_SETFOREGROUND
}

// SingleInstance shu nomdagi nusxa allaqachon ishlayaptimi — tekshiradi.
// true qaytarsa, bu birinchi nusxa.
func SingleInstance(name string) bool {
	n, _ := windows.UTF16PtrFromString(`Local\` + name)
	_, err := windows.CreateMutex(nil, false, n)
	return !errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

// SingleInstanceFree shu nomdagi mutex hech kim tomonidan ushlanmaganmi (yaratmasdan tekshiradi).
func SingleInstanceFree(name string) bool {
	n, _ := windows.UTF16PtrFromString(`Local\` + name)
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, n)
	if err != nil {
		return true
	}
	windows.CloseHandle(h)
	return false
}
