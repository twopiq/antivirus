package engine

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/sigdb"
)

// peInfo — PE faylni statik tahlil natijasi.
type peInfo struct {
	ep       int // kirish nuqtasining fayldagi siljishi (-1 — noma'lum)
	score    int
	reasons  []string
	sections []peSection
}

type peSection struct {
	name string
	data []byte
}

var packerSections = map[string]string{
	"upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
	".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
	".themida": "Themida", ".winlice": "WinLicense", ".enigma1": "Enigma", ".enigma2": "Enigma", "pec2": "PECompact",
	".perplex": "Perplex", ".yp": "Y0da", ".packed": "Packer", ".spack": "SimplePack", ".mew": "MEW", "fsg!": "FSG",
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var e float64
	n := float64(len(b))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func (p *peInfo) add(score int, reason string) {
	p.score += score
	p.reasons = append(p.reasons, reason)
}

// analyzePE PE faylni tahlil qiladi: kirish nuqtasi, bo'limlar va shubhali belgilar.
func analyzePE(data []byte) *peInfo {
	info := &peInfo{ep: -1}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return info
	}
	defer f.Close()

	var epRVA uint32
	var isDLL bool
	var stamp uint32 = f.FileHeader.TimeDateStamp
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		epRVA = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		epRVA = oh.AddressOfEntryPoint
	}
	isDLL = f.FileHeader.Characteristics&0x2000 != 0

	const (
		memExec  = 0x20000000
		memWrite = 0x80000000
	)
	epSection := -1
	for i, s := range f.Sections {
		start := int(s.Offset)
		end := start + int(s.Size)
		if start < 0 || start > len(data) {
			start = len(data)
		}
		if end > len(data) || end < start {
			end = len(data)
		}
		raw := data[start:end]
		info.sections = append(info.sections, peSection{name: s.Name, data: raw})

		if epRVA != 0 && epRVA >= s.VirtualAddress && epRVA < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			epSection = i
			if off := int(s.Offset) + int(epRVA-s.VirtualAddress); off < len(data) {
				info.ep = off
			}
		}
		name := strings.ToLower(strings.TrimRight(s.Name, "\x00"))
		if p, ok := packerSections[name]; ok {
			info.add(2, "paker: "+p)
		}
		exec := s.Characteristics&memExec != 0
		if exec && s.Characteristics&memWrite != 0 {
			info.add(2, "yoziladigan va bajariladigan bo'lim "+s.Name)
		}
		if exec && len(raw) > 1024 && entropy(raw) > 7.2 {
			info.add(2, fmt.Sprintf("shifrlangan/siqilgan kod (%s)", s.Name))
		}
	}
	if epRVA != 0 && !isDLL {
		switch {
		case epSection < 0:
			info.add(3, "kirish nuqtasi bo'limlardan tashqarida")
		case f.Sections[epSection].Characteristics&memExec == 0:
			info.add(2, "kirish nuqtasi bajarilmaydigan bo'limda")
		case epSection == len(f.Sections)-1 && len(f.Sections) > 1:
			info.add(2, "kirish nuqtasi oxirgi bo'limda")
		}
	}

	imports, _ := f.ImportedSymbols()
	has := map[string]bool{}
	for _, s := range imports {
		fn := s
		if i := strings.IndexByte(s, ':'); i >= 0 {
			fn = s[:i]
		}
		fn = strings.TrimSuffix(strings.TrimSuffix(fn, "A"), "W")
		has[strings.ToLower(fn)] = true
	}
	hasAny := func(names ...string) bool {
		for _, n := range names {
			if has[n] {
				return true
			}
		}
		return false
	}
	if !isDLL {
		switch {
		case len(imports) == 0:
			info.add(2, "import jadvali yo'q")
		case len(imports) <= 4 && has["loadlibrary"] && has["getprocaddress"]:
			info.add(2, "importlar yashirilgan (faqat LoadLibrary/GetProcAddress)")
		}
	}
	if hasAny("virtualallocex", "ntallocatevirtualmemory") && hasAny("writeprocessmemory", "ntwritevirtualmemory") &&
		hasAny("createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "rtlcreateuserthread") {
		info.add(3, "boshqa jarayonga kod kiritish (injection)")
	}
	if hasAny("ntunmapviewofsection", "zwunmapviewofsection") && hasAny("setthreadcontext", "wow64setthreadcontext") && has["resumethread"] {
		info.add(3, "jarayonni almashtirish (process hollowing)")
	}
	if hasAny("setwindowshookex") && hasAny("getasynckeystate", "getkeystate", "getkeyboardstate") {
		info.add(1, "klaviaturani kuzatish")
	}
	if has["urldownloadtofile"] && hasAny("shellexecute", "winexec", "createprocess") {
		info.add(2, "fayl yuklab olib ishga tushiradi")
	}
	if has["isdebuggerpresent"] && has["checkremotedebuggerpresent"] {
		info.add(1, "tuzatuvchidan (debugger) yashirinish")
	}
	if stamp == 0 || int64(stamp) > time.Now().Add(48*time.Hour).Unix() {
		info.add(1, "noto'g'ri kompilyatsiya sanasi")
	}
	return info
}

// sectionHashes bo'lim xeshlarini baza bilan solishtiradi.
func sectionMatch(db *sigdb.DB, info *peInfo) (string, bool) {
	if !db.HasSections() {
		return "", false
	}
	for _, s := range info.sections {
		if len(s.data) == 0 {
			continue
		}
		m := md5.Sum(s.data)
		h := sigdb.Hashes{MD5: m[:]}
		if db.NeedSHA1() {
			x := sha1.Sum(s.data)
			h.SHA1 = x[:]
		}
		x := sha256.Sum256(s.data)
		h.SHA256 = x[:]
		if n, ok := db.LookupSection(h, uint32(len(s.data))); ok {
			return n, true
		}
	}
	return "", false
}

// peThreshold — shu balldan yuqori PE fayllar shubhali deb belgilanadi.
const peThreshold = 6
