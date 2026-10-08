// Package system operatsion tizimga bog'liq funksiyalar: disklar, jarayonlar,
// avtoyuklash (autorun) yozuvlari, administrator huquqlari va konsol.
package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Proc — ishlab turgan jarayon.
type Proc struct {
	PID  uint32
	Name string
	Path string
}

// AutorunKind — avtoyuklash yozuvi turi.
type AutorunKind int

const (
	AutorunRegistry AutorunKind = iota // reestrdagi Run kaliti qiymati
	AutorunFile                        // Startup papkasidagi fayl
	AutorunWinlogon                    // Winlogon Shell/Userinit qiymati
)

// Autorun — kompyuter yoqilganda avtomatik ishga tushadigan yozuv.
type Autorun struct {
	Kind     AutorunKind
	Location string // reestr kaliti yoki papka
	Name     string // qiymat yoki fayl nomi
	Command  string // buyruq satri
	Paths    []string
	// Winlogon uchun: kutilgan standart qiymat.
	Default string

	root uintptr // registry.Key (faqat Windows)
	key  string
}

// DataDir dastur ma'lumotlari (baza, karantin, jurnallar) saqlanadigan papka.
// QALQON_HOME muhit o'zgaruvchisi bilan o'zgartirish mumkin.
func DataDir() string {
	if d := os.Getenv("QALQON_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Qalqon")
		}
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "qalqon")
	}
	return "qalqon-data"
}

// ExpandPercent Windows uslubidagi %VAR% o'zgaruvchilarni ochadi.
func ExpandPercent(s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			b.WriteString(s)
			break
		}
		name := s[i+1 : i+1+j]
		if v, ok := os.LookupEnv(name); ok && name != "" {
			b.WriteString(s[:i])
			b.WriteString(v)
		} else {
			b.WriteString(s[:i+1+j+1])
		}
		s = s[i+1+j+1:]
	}
	return b.String()
}

var launcherNames = map[string]bool{
	"wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true,
	"regsvr32.exe": true, "powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
}

var payloadExts = []string{".exe", ".dll", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".scr", ".com", ".pif", ".cpl"}

// CommandPaths buyruq satridan bajariladigan fayl yo'llarini ajratib oladi:
// birinchisi — dasturning o'zi, keyingilari — skript/DLL argumentlari
// (masalan  wscript.exe "C:\Users\u\AppData\x.vbs").
func CommandPaths(cmd string) []string {
	cmd = strings.TrimSpace(ExpandPercent(cmd))
	if cmd == "" {
		return nil
	}
	var exe, rest string
	if cmd[0] == '"' {
		if j := strings.IndexByte(cmd[1:], '"'); j >= 0 {
			exe, rest = cmd[1:1+j], cmd[2+j:]
		} else {
			exe = cmd[1:]
		}
	} else {
		exe, rest = cmd, ""
		lower := strings.ToLower(cmd)
		best := -1
		for _, ext := range payloadExts {
			k := 0
			for {
				i := strings.Index(lower[k:], ext)
				if i < 0 {
					break
				}
				end := k + i + len(ext)
				if end == len(lower) || lower[end] == ' ' || lower[end] == ',' {
					if best < 0 || end < best {
						best = end
					}
					break
				}
				k = end
			}
		}
		if best > 0 {
			exe, rest = cmd[:best], cmd[best:]
		} else if sp := strings.IndexByte(cmd, ' '); sp > 0 {
			exe, rest = cmd[:sp], cmd[sp:]
		}
	}
	out := []string{resolveExe(strings.TrimSpace(exe))}
	if launcherNames[strings.ToLower(baseName(out[0]))] {
		for _, a := range splitArgs(rest) {
			a = strings.TrimRight(strings.SplitN(a, ",", 2)[0], " ")
			la := strings.ToLower(a)
			for _, ext := range payloadExts {
				if strings.HasSuffix(la, ext) && !strings.HasPrefix(la, "/") && !strings.HasPrefix(la, "-") {
					out = append(out, resolveExe(a))
					break
				}
			}
		}
	}
	return out
}

func resolveExe(p string) string {
	if p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, `\/`) {
		return p
	}
	if runtime.GOOS == "windows" {
		if sr := os.Getenv("SystemRoot"); sr != "" {
			cand := filepath.Join(sr, "System32", p)
			if !strings.Contains(filepath.Base(p), ".") {
				cand += ".exe"
			}
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return p
}

func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// IsLauncher dastur skript/DLL ishga tushiruvchi tizim vositasimi (wscript, mshta, ...).
func IsLauncher(path string) bool {
	return launcherNames[strings.ToLower(baseName(path))]
}

// InUserWritableDir yo'l odatda zararli dasturlar yashiriladigan papkadami
// (Temp, AppData, ProgramData, Public, Recycle Bin) — tekshiradi.
func InUserWritableDir(p string) bool {
	lp := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, s := range []string{"/temp/", "/tmp/", "/appdata/", "/programdata/", "/users/public/", "/$recycle.bin/"} {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

// baseName fayl nomini ajratadi ("\" va "/" ikkalasini ham ajratgich deb hisoblaydi).
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
