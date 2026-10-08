// Package system operatsion tizimga bog'liq funksiyalar: disklar, jarayonlar,
// avtoyuklash (autorun) yozuvlari, administrator huquqlari va konsol.
package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
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
	AutorunWinlogon                    // standart qiymatga ega reestr qiymati (Winlogon, AppInit_DLLs)
	AutorunTask                        // rejalashtirilgan vazifa (Task Scheduler)
	AutorunService                     // xizmat yoki drayver
	AutorunIFEO                        // Image File Execution Options "Debugger" o'g'irlash
)

// String yozuv turining o'zbekcha nomi.
func (k AutorunKind) String() string {
	return [...]string{"Reestr (Run)", "Startup papkasi", "Tizim qiymati", "Rejalashtirilgan vazifa", "Xizmat", "IFEO"}[k]
}

// Autorun — kompyuter yoqilganda avtomatik ishga tushadigan yozuv.
type Autorun struct {
	Kind     AutorunKind
	Location string // reestr kaliti yoki papka
	Name     string // qiymat yoki fayl nomi
	Command  string // buyruq satri
	Paths    []string
	// Winlogon uchun: kutilgan standart qiymat.
	Default string
	// Microsoft — Windows'ning o'z yozuvi (masalan \Microsoft\ vazifalari).
	Microsoft bool
	// Disabled — yozuv o'chirib qo'yilgan (xizmat Start=4 yoki vazifa o'chirilgan).
	Disabled bool

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

// TaskActions Task Scheduler XML faylidan (UTF-16 yoki UTF-8) buyruqlarni ajratadi.
func TaskActions(data []byte) (cmds []string, enabled bool) {
	text := decodeUTF16(data)
	enabled = true
	if i := strings.Index(text, "<Settings>"); i >= 0 {
		if j := strings.Index(text[i:], "</Settings>"); j >= 0 && strings.Contains(text[i:i+j], "<Enabled>false</Enabled>") {
			enabled = false
		}
	}
	for {
		i := strings.Index(text, "<Exec>")
		if i < 0 {
			break
		}
		j := strings.Index(text[i:], "</Exec>")
		if j < 0 {
			break
		}
		block := text[i : i+j]
		text = text[i+j:]
		cmd := xmlText(block, "Command")
		if cmd == "" {
			continue
		}
		if !strings.HasPrefix(cmd, `"`) && strings.Contains(cmd, " ") {
			cmd = `"` + cmd + `"`
		}
		if args := xmlText(block, "Arguments"); args != "" {
			cmd += " " + args
		}
		cmds = append(cmds, cmd)
	}
	return cmds, enabled
}

func xmlText(s, tag string) string {
	i := strings.Index(s, "<"+tag+">")
	if i < 0 {
		return ""
	}
	s = s[i+len(tag)+2:]
	j := strings.Index(s, "</"+tag+">")
	if j < 0 {
		return ""
	}
	r := strings.NewReplacer("&quot;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&apos;", "'")
	return strings.TrimSpace(r.Replace(s[:j]))
}

func decodeUTF16(b []byte) string {
	if len(b) >= 2 && (b[0] == 0xFF && b[1] == 0xFE || len(b) > 4 && b[1] == 0 && b[3] == 0) {
		if b[0] == 0xFF && b[1] == 0xFE {
			b = b[2:]
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		return string(utf16.Decode(u))
	}
	return strings.TrimPrefix(string(b), "\uFEFF")
}

// HostsIssue — hosts faylidagi shubhali yozuv.
type HostsIssue struct {
	Line   int
	Text   string
	Host   string
	Reason string
	Severe bool
}

// securityDomains — zararli dasturlar odatda bloklaydigan xavfsizlik va yangilanish saytlari.
var securityDomains = []string{
	"microsoft.com", "windowsupdate.com", "windows.com", "update.microsoft.com", "kaspersky.com", "kaspersky.ru",
	"eset.com", "avast.com", "avg.com", "drweb.com", "drweb.ru", "malwarebytes.com", "bitdefender.com",
	"norton.com", "mcafee.com", "sophos.com", "virustotal.com", "clamav.net", "abuse.ch", "eicar.org",
}

// sensitiveDomains — soxta manzilga yo'naltirilishi xavfli saytlar (fishing).
var sensitiveDomains = append([]string{
	"live.com", "office.com", "msn.com", "bing.com", "google.com", "youtube.com", "gmail.com", "facebook.com",
	"instagram.com", "whatsapp.com", "telegram.org", "t.me", "vk.com", "mail.ru", "yandex.ru", "yandex.com",
	"ok.ru", "apple.com", "icloud.com", "paypal.com", "github.com", "click.uz", "payme.uz", "uzum.uz",
	"kapitalbank.uz", "gov.uz", "my.gov.uz", "soliq.uz",
}, securityDomains...)

func matchDomain(host string, list []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range list {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func isSensitive(host string) bool { return matchDomain(host, sensitiveDomains) }

// CheckHosts hosts fayli mazmunini tahlil qiladi.
func CheckHosts(data []byte) []HostsIssue {
	var out []HostsIssue
	for n, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		ip := f[0]
		local := ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "::"
		for _, host := range f[1:] {
			h := strings.ToLower(host)
			if h == "localhost" || h == "localhost.localdomain" || h == "local" {
				continue
			}
			switch {
			case isSensitive(h) && !local:
				out = append(out, HostsIssue{Line: n + 1, Text: strings.TrimSpace(line), Host: h, Reason: "sayt soxta manzilga yo'naltirilgan", Severe: true})
			case local && matchDomain(h, securityDomains):
				out = append(out, HostsIssue{Line: n + 1, Text: strings.TrimSpace(line), Host: h, Reason: "xavfsizlik/yangilanish sayti bloklangan", Severe: true})
			case local && isSensitive(h):
				out = append(out, HostsIssue{Line: n + 1, Text: strings.TrimSpace(line), Host: h, Reason: "sayt bloklangan (ehtimol foydalanuvchi o'zi bloklagan)"})
			case !local:
				out = append(out, HostsIssue{Line: n + 1, Text: strings.TrimSpace(line), Host: h, Reason: "boshqa manzilga yo'naltirilgan"})
			}
		}
	}
	return out
}

// DisableHostsLines berilgan satrlarni izohga aylantiradi (# Qalqon: ...).
func DisableHostsLines(data []byte, lines map[int]bool) []byte {
	ls := strings.Split(string(data), "\n")
	for i := range ls {
		if lines[i+1] {
			ls[i] = "# Qalqon o'chirdi: " + strings.TrimRight(ls[i], "\r")
		}
	}
	return []byte(strings.Join(ls, "\n"))
}

// NormalizeDriverPath xizmat/drayver yo'llarini oddiy ko'rinishga keltiradi:
// "\SystemRoot\System32\x.sys", "\??\C:\x.sys", "System32\drivers\x.sys".
func NormalizeDriverPath(p, systemRoot string) string {
	p = strings.TrimSpace(p)
	lp := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lp, `\systemroot\`):
		return systemRoot + p[len(`\SystemRoot`):]
	case strings.HasPrefix(lp, `\??\`):
		return p[4:]
	case strings.HasPrefix(lp, `system32\`) || strings.HasPrefix(lp, `syswow64\`):
		return systemRoot + `\` + p
	}
	return p
}
