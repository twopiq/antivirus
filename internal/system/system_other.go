//go:build !windows

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// InitConsole Windows bo'lmagan tizimlarda hech narsa qilmaydi; terminal ranglarni qo'llaydi.
func InitConsole() bool { return true }

// IsAdmin joriy jarayon root huquqi bilan ishlayaptimi.
func IsAdmin() bool { return os.Geteuid() == 0 }

// Elevate faqat Windows'da ishlaydi.
func Elevate(args []string) error { return errors.New("faqat Windows'da qo'llab-quvvatlanadi") }

// Drives qattiq disklar va olinadigan qurilmalarni qaytaradi.
func Drives() (fixed, removable []string) {
	for _, pat := range []string{"/media/*/*", "/run/media/*/*", "/mnt/*"} {
		m, _ := filepath.Glob(pat)
		removable = append(removable, m...)
	}
	return []string{"/"}, removable
}

// Processes ishlab turgan jarayonlar ro'yxati (/proc orqali).
func Processes() ([]Proc, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []Proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		out = append(out, Proc{PID: uint32(pid), Name: filepath.Base(exe), Path: exe})
	}
	return out, nil
}

// KillProcess jarayonni to'xtatadi.
func KillProcess(pid uint32) error { return syscall.Kill(int(pid), syscall.SIGKILL) }

// Autoruns ~/.config/autostart dagi yozuvlar.
func Autoruns() []Autorun {
	var out []Autorun
	if d, err := os.UserConfigDir(); err == nil {
		dir := filepath.Join(d, "autostart")
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			out = append(out, Autorun{Kind: AutorunFile, Location: dir, Name: e.Name(), Command: p, Paths: []string{p}})
		}
	}
	return out
}

// RemoveAutorun avtoyuklash yozuvini o'chiradi.
func RemoveAutorun(a Autorun) error {
	if a.Kind == AutorunFile {
		return os.Remove(filepath.Join(a.Location, a.Name))
	}
	return errors.New("qo'llab-quvvatlanmaydi")
}

// IsHiddenSystem Windows'dagi "yashirin+tizim" atributining o'xshashi: nuqta bilan boshlanadigan nom.
func IsHiddenSystem(path string) bool {
	return len(filepath.Base(path)) > 1 && filepath.Base(path)[0] == '.'
}

// Unhide Windows bo'lmagan tizimlarda hech narsa qilmaydi.
func Unhide(path string) error { return nil }

// QuickScanDirs tezkor tekshiruv papkalari.
func QuickScanDirs() []string {
	h, _ := os.UserHomeDir()
	return existing(filepath.Join(h, "Downloads"), filepath.Join(h, "Desktop"), os.TempDir(), filepath.Join(h, ".config", "autostart"))
}

// MonitorDirs real vaqtda kuzatiladigan papkalar.
func MonitorDirs() []string {
	h, _ := os.UserHomeDir()
	return existing(filepath.Join(h, "Downloads"), filepath.Join(h, "Desktop"))
}

func existing(ps ...string) []string {
	var out []string
	for _, p := range ps {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// WinlogonModified faqat Windows uchun ma'noga ega.
func WinlogonModified(a Autorun) bool { return false }
