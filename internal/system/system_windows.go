//go:build windows

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// InitConsole konsolni UTF-8 va ANSI ranglarga moslaydi. Ranglar
// qo'llab-quvvatlansa true qaytaradi.
func InitConsole() bool {
	_ = windows.SetConsoleOutputCP(65001)
	_ = windows.SetConsoleCP(65001)
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

// IsAdmin jarayon administrator huquqi bilan ishlayaptimi.
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Elevate dasturni administrator sifatida qayta ishga tushiradi (UAC oynasi chiqadi).
func Elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	cwd, _ := os.Getwd()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(cwd)
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_NORMAL)
}

// Drives qattiq disklar va olinadigan (USB) disklar ro'yxati.
func Drives() (fixed, removable []string) {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, nil
	}
	var cur []uint16
	for _, c := range buf[:n] {
		if c != 0 {
			cur = append(cur, c)
			continue
		}
		if len(cur) == 0 {
			continue
		}
		root := windows.UTF16ToString(cur)
		cur = cur[:0]
		p, _ := windows.UTF16PtrFromString(root)
		switch windows.GetDriveType(p) {
		case windows.DRIVE_FIXED:
			fixed = append(fixed, root)
		case windows.DRIVE_REMOVABLE:
			removable = append(removable, root)
		}
	}
	return fixed, removable
}

// Processes ishlab turgan jarayonlar ro'yxati.
func Processes() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []Proc
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := Proc{PID: pe.ProcessID, Name: windows.UTF16ToString(pe.ExeFile[:])}
		if pe.ProcessID > 4 {
			p.Path = processPath(pe.ProcessID)
		}
		out = append(out, p)
	}
	return out, nil
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// KillProcess jarayonni majburan to'xtatadi.
func KillProcess(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

type runKey struct {
	root registry.Key
	name string
	path string
}

var runPaths = []string{
	`Software\Microsoft\Windows\CurrentVersion\Run`,
	`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
}

// runKeys barcha foydalanuvchilar (HKEY_USERS) va kompyuter (HKLM) Run kalitlari.
func runKeys() []runKey {
	var out []runKey
	for _, p := range runPaths {
		out = append(out, runKey{registry.LOCAL_MACHINE, "HKLM", p})
	}
	out = append(out,
		runKey{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		runKey{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	)
	sids := userSIDs()
	if len(sids) == 0 {
		for _, p := range runPaths {
			out = append(out, runKey{registry.CURRENT_USER, "HKCU", p})
		}
	}
	for _, sid := range sids {
		for _, p := range runPaths {
			out = append(out, runKey{registry.USERS, "HKU", sid + `\` + p})
		}
	}
	return out
}

// userSIDs HKEY_USERS dagi yuklangan foydalanuvchi profillari.
func userSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			if sk, err := registry.OpenKey(registry.USERS, n+`\Software`, registry.QUERY_VALUE); err == nil {
				sk.Close()
				out = append(out, n)
			}
		}
	}
	return out
}

// userProfiles C:\Users ichidagi haqiqiy foydalanuvchi papkalari.
func userProfiles() []string {
	base := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	if pub := os.Getenv("PUBLIC"); pub != "" {
		base = filepath.Dir(pub)
	}
	ents, _ := os.ReadDir(base)
	var out []string
	for _, e := range ents {
		switch strings.ToLower(e.Name()) {
		case "public", "default", "default user", "all users", "defaultapppool":
			continue
		}
		if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}

func startupDirs() []string {
	dirs := []string{knownDir(windows.FOLDERID_Startup), knownDir(windows.FOLDERID_CommonStartup)}
	for _, u := range userProfiles() {
		dirs = append(dirs, filepath.Join(u, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	return existing(dirs...)
}

const winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

// Autoruns reestrdagi Run kalitlari, Startup papkalari va Winlogon qiymatlarini qaytaradi.
func Autoruns() []Autorun {
	var out []Autorun
	for _, rk := range runKeys() {
		k, err := registry.OpenKey(rk.root, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			v, _, err := k.GetStringValue(n)
			if err != nil {
				continue
			}
			out = append(out, Autorun{Kind: AutorunRegistry, Location: rk.name + `\` + rk.path, Name: n, Command: v, Paths: CommandPaths(v), root: uintptr(rk.root), key: rk.path})
		}
		k.Close()
	}
	for _, dir := range startupDirs() {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			out = append(out, Autorun{Kind: AutorunFile, Location: dir, Name: e.Name(), Command: p, Paths: []string{p}})
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKey, registry.QUERY_VALUE); err == nil {
		sysRoot := os.Getenv("SystemRoot")
		if sysRoot == "" {
			sysRoot = `C:\Windows`
		}
		defaults := map[string]string{"Shell": "explorer.exe", "Userinit": sysRoot + `\system32\userinit.exe,`}
		for _, n := range []string{"Shell", "Userinit"} {
			v, _, err := k.GetStringValue(n)
			if err != nil {
				continue
			}
			out = append(out, Autorun{Kind: AutorunWinlogon, Location: `HKLM\` + winlogonKey, Name: n, Command: v, Paths: CommandPaths(strings.Split(v, ",")[0]), Default: defaults[n], root: uintptr(registry.LOCAL_MACHINE), key: winlogonKey})
		}
		k.Close()
	}
	out = append(out, appInit()...)
	out = append(out, ifeo()...)
	out = append(out, scheduledTasks()...)
	out = append(out, services()...)
	return out
}

// WinlogonModified Winlogon qiymati standartdan farq qiladimi.
func WinlogonModified(a Autorun) bool {
	if a.Kind != AutorunWinlogon {
		return false
	}
	if a.Name == "AppInit_DLLs" {
		return strings.TrimSpace(a.Command) != ""
	}
	norm := func(s string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), ",") }
	if a.Name == "Shell" {
		return norm(a.Command) != "explorer.exe" && !strings.HasSuffix(norm(a.Command), `\explorer.exe`)
	}
	return !strings.HasSuffix(norm(a.Command), `\userinit.exe`)
}

// RemoveAutorun yozuvni o'chiradi (Winlogon uchun — standart qiymatni tiklaydi).
func RemoveAutorun(a Autorun) error {
	switch a.Kind {
	case AutorunRegistry:
		k, err := registry.OpenKey(registry.Key(a.root), a.key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.DeleteValue(a.Name)
	case AutorunWinlogon:
		if a.Default == "" && a.Name != "AppInit_DLLs" {
			return errors.New("standart qiymat noma'lum")
		}
		k, err := registry.OpenKey(registry.Key(a.root), a.key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetStringValue(a.Name, a.Default)
	case AutorunFile:
		return os.Remove(filepath.Join(a.Location, a.Name))
	}
	return removeExtra(a)
}

// IsHiddenSystem fayl/papkada "yashirin" yoki "tizim" atributi bormi.
func IsHiddenSystem(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return a&(windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM) != 0
}

// Unhide "yashirin", "tizim" va "faqat o'qish" atributlarini olib tashlaydi.
func Unhide(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	a &^= windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_READONLY
	if a == 0 {
		a = windows.FILE_ATTRIBUTE_NORMAL
	}
	return windows.SetFileAttributes(p, a)
}

func knownDir(id *windows.KNOWNFOLDERID) string {
	d, _ := windows.KnownFolderPath(id, 0)
	return d
}

// QuickScanDirs tezkor tekshiruv uchun eng xavfli papkalar (barcha foydalanuvchilar uchun).
func QuickScanDirs() []string {
	dirs := []string{
		knownDir(windows.FOLDERID_Downloads),
		knownDir(windows.FOLDERID_Desktop),
		os.TempDir(),
		filepath.Join(os.Getenv("SystemRoot"), "Temp"),
		os.Getenv("APPDATA"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp"),
		os.Getenv("PUBLIC"),
	}
	dirs = append(dirs, startupDirs()...)
	for _, u := range userProfiles() {
		dirs = append(dirs,
			filepath.Join(u, "Downloads"),
			filepath.Join(u, "Desktop"),
			filepath.Join(u, `AppData\Roaming`),
			filepath.Join(u, `AppData\Local\Temp`),
		)
	}
	return existing(dirs...)
}

// MonitorDirs real vaqtda kuzatiladigan papkalar.
func MonitorDirs() []string {
	return existing(
		knownDir(windows.FOLDERID_Downloads),
		knownDir(windows.FOLDERID_Desktop),
		knownDir(windows.FOLDERID_Documents),
		knownDir(windows.FOLDERID_Startup),
		knownDir(windows.FOLDERID_CommonStartup),
	)
}

// MonitorRiskyDirs real vaqtda faqat xavfli turdagi fayllari kuzatiladigan
// "shovqinli" papkalar (Temp, AppData).
func MonitorRiskyDirs() []string {
	return existing(os.TempDir(), os.Getenv("APPDATA"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp"), os.Getenv("PUBLIC"))
}

func existing(ps ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range ps {
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			seen[strings.ToLower(p)] = true
			out = append(out, p)
		}
	}
	return out
}
