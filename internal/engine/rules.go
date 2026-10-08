package engine

import (
	"bytes"
	"path/filepath"
	"strings"
)

// Severity — tahdid darajasi.
type Severity int

const (
	// Suspicious — shubhali: foydalanuvchi qaror qiladi.
	Suspicious Severity = iota + 1
	// Malicious — aniq zararli.
	Malicious
)

func (s Severity) String() string {
	if s == Malicious {
		return "Xavfli"
	}
	return "Shubhali"
}

// group — kamida Min ta naqsh topilishi kerak bo'lgan naqshlar to'plami.
type group struct {
	Min      int
	Patterns []string
}

// rule — fayl mazmuniga qo'llanadigan qoida. Barcha guruhlar bajarilsa, qoida ishlaydi.
type rule struct {
	Name     string
	Severity Severity
	Exts     []string // bo'sh bo'lsa — barcha fayllar
	NoCase   bool     // true bo'lsa naqshlar kichik harflarda yoziladi va matn kichik harflarga o'tkaziladi
	Groups   []group
}

var scriptExts = []string{".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".lnk"}

var rules = []rule{
	{
		// Fleshkalardagi "yorliq virusi" (shortcut virus) va shunga o'xshash skript qurtlari.
		Name: "Worm.Script.USBSpreader", Severity: Malicious, Exts: scriptExts, NoCase: true,
		Groups: []group{
			{1, []string{"wscript.shell", "scripting.filesystemobject", "shell.application"}},
			{3, []string{"autorun.inf", "drivetype", ".drives", "copyfile", "createshortcut", `\currentversion\run`, "regwrite", ".attributes", `specialfolders("startup")`, "attrib +h"}},
		},
	},
	{
		Name: "Trojan.Script.Downloader", Severity: Suspicious, Exts: scriptExts, NoCase: true,
		Groups: []group{
			{1, []string{"msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "downloadfile(", "downloadstring(", "invoke-webrequest", "bitsadmin /transfer", "certutil -urlcache", "net.webclient"}},
			{1, []string{"adodb.stream", "savetofile", "shellexecute", ".run(", ".run ", "start-process", "iex", "invoke-expression", ".exec("}},
		},
	},
	{
		Name: "Trojan.PowerShell.HiddenEncoded", Severity: Suspicious, Exts: scriptExts, NoCase: true,
		Groups: []group{
			{1, []string{"powershell", "pwsh"}},
			{1, []string{"-enc ", "-encodedcommand", "-e jab", "frombase64string"}},
			{1, []string{"-w hidden", "-windowstyle hidden", "-win hidden", "-nop", "bypass"}},
		},
	},
	{
		Name: "Trojan.Batch.Persistence", Severity: Suspicious, Exts: []string{".bat", ".cmd"}, NoCase: true,
		Groups: []group{
			{1, []string{"reg add"}},
			{1, []string{`\currentversion\run`, `\winlogon`}},
			{1, []string{"attrib +h", "attrib +s", "taskkill", "schtasks /create"}},
		},
	},
	{
		Name: "Ransom.Script.ShadowCopyDelete", Severity: Malicious, Exts: []string{".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"}, NoCase: true,
		Groups: []group{{1, []string{"vssadmin delete shadows", "vssadmin.exe delete shadows", "shadowcopy delete", "wbadmin delete catalog", "recoveryenabled no"}}},
	},
	{
		// Naqshlar teskari yozilgan, aks holda qalqon.exe ning o'zi bu qoidaga tushadi:
		// "delete shadows /all /quiet", "shadowcopy delete", "recoveryenabled no".
		Name: "Ransom.Generic.ShadowCopyDelete", Severity: Suspicious, Exts: []string{".exe", ".dll", ".scr"},
		Groups: []group{{1, revAll("teiuq/ lla/ swodahs eteled", "teiuQ/ llA/ swodahS eteleD", "eteled ypocwodahs", "oN delbaneyrevocer", "on delbaneyrevocer")}},
	},
	{
		// "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://" (teskari yozilgan).
		Name: "Riskware.CoinMiner", Severity: Suspicious,
		Groups: []group{{1, revAll("//:pct+mutarts", "//:lss+mutarts", "//:pct+2mutarts")}},
	},
	{
		Name: "Trojan.HTA.Dropper", Severity: Suspicious, Exts: []string{".hta"}, NoCase: true,
		Groups: []group{
			{1, []string{"activexobject", "createobject"}},
			{1, []string{"wscript.shell", "shell.application"}},
			{1, []string{".run", ".exec", "shellexecute"}},
		},
	},
}

func init() {
	for i := range rules {
		if !rules[i].NoCase {
			continue
		}
		for g := range rules[i].Groups {
			for p := range rules[i].Groups[g].Patterns {
				rules[i].Groups[g].Patterns[p] = strings.ToLower(rules[i].Groups[g].Patterns[p])
			}
		}
	}
}

func (r *rule) appliesTo(ext string) bool {
	if len(r.Exts) == 0 {
		return true
	}
	for _, e := range r.Exts {
		if e == ext {
			return true
		}
	}
	return false
}

func (r *rule) match(data, lower []byte) bool {
	hay := data
	if r.NoCase {
		hay = lower
	}
	for _, g := range r.Groups {
		n := 0
		for _, p := range g.Patterns {
			if bytes.Contains(hay, []byte(p)) {
				n++
				if n >= g.Min {
					break
				}
			}
		}
		if n < g.Min {
			return false
		}
	}
	return true
}

// lowerASCII ASCII harflarni kichiklashtiradi; UTF-16LE matndagi nol baytlarni
// olib tashlaydi, shunda .lnk va Unicode skriptlardagi satrlar ham topiladi.
func lowerASCII(data []byte, stripNUL bool) []byte {
	out := make([]byte, 0, len(data))
	for _, c := range data {
		if c == 0 && stripNUL {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return out
}

// matchRules fayl mazmuniga mos qoidalarni qaytaradi.
func matchRules(name string, data []byte) []Threat {
	ext := strings.ToLower(filepath.Ext(name))
	var lower []byte
	var out []Threat
	for i := range rules {
		r := &rules[i]
		if !r.appliesTo(ext) {
			continue
		}
		if r.NoCase && lower == nil {
			lower = lowerASCII(data, true)
		}
		if r.match(data, lower) {
			out = append(out, Threat{Name: r.Name, Severity: r.Severity, Kind: KindRule})
		}
	}
	return out
}

func init() {
	rules = append(rules, rule{
		// HTML "smuggling": brauzer ichida zararli faylni yig'ib, avtomatik yuklab berish.
		Name: "Heur.HTML.Smuggling", Severity: Suspicious, Exts: []string{".html", ".htm", ".shtml", ".svg", ".xhtml"}, NoCase: true,
		Groups: []group{
			{1, []string{"mssaveoropenblob", ".download=", ".download =", "setattribute(\"download\"", "setattribute('download'"}},
			{1, []string{"atob(", "new blob", "uint8array", "fromcharcode"}},
			{1, []string{".click()", "mssaveoropenblob"}},
		},
	})
}

// revAll teskari yozilgan naqshlarni asl holiga qaytaradi.
func revAll(ps ...string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		b := []byte(p)
		for l, r := 0, len(b)-1; l < r; l, r = l+1, r-1 {
			b[l], b[r] = b[r], b[l]
		}
		out[i] = string(b)
	}
	return out
}
