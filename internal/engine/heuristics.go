package engine

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
)

var executableExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true, ".cmd": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true,
	".ps1": true, ".msi": true, ".jar": true, ".cpl": true,
}

var documentExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true,
	".pptx": true, ".txt": true, ".rtf": true, ".jpg": true, ".jpeg": true, ".png": true,
	".gif": true, ".bmp": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
	".zip": true, ".rar": true, ".7z": true, ".html": true, ".htm": true, ".csv": true,
}

// checkName faqat fayl nomiga qarab ishlaydigan evristik tekshiruvlar.
func checkName(name string) []Threat {
	base := filepath.Base(name)
	var out []Threat
	// Unicode RTLO belgisi: "photo‮gpj.exe" Explorer'da "photoexe.jpg" bo'lib ko'rinadi.
	if strings.ContainsRune(base, '‮') {
		out = append(out, Threat{Name: "Heur.RTLO.SpoofedName", Severity: Malicious, Kind: KindHeuristic})
	}
	ext := strings.ToLower(filepath.Ext(base))
	if executableExts[ext] {
		stem := strings.TrimRight(strings.TrimSuffix(base, filepath.Ext(base)), " .")
		inner := strings.ToLower(filepath.Ext(stem))
		if documentExts[inner] {
			out = append(out, Threat{Name: "Heur.DoubleExtension", Severity: Suspicious, Kind: KindHeuristic})
		}
	}
	return out
}

// isPE fayl Windows bajariladigan (PE) formatdami — tekshiradi.
func isPE(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(data[0x3c:]))
	return off > 0 && off+4 <= len(data) && bytes.Equal(data[off:off+4], []byte("PE\x00\x00"))
}

var lnkHeader = []byte{0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}

// eicarHead EICAR test satrining boshlanishi va oxiri. To'liq satr dastur ichida
// yozilmaydi — aks holda boshqa antiviruslar qalqon.exe ni EICAR deb aniqlashi mumkin.
const (
	eicarHead = `X5O!P%@AP[4\PZX54(P^)7CC)7}$`
	eicarTail = `-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

// isEICAR standart bo'yicha tekshiradi: fayl EICAR satri bilan boshlanadi va
// (bo'shliqlardan tashqari) 128 baytdan oshmaydi.
func isEICAR(data []byte) bool {
	d := bytes.TrimRight(data, " \t\r\n\x1a")
	return len(d) <= 128 && len(d) == len(eicarHead)+len("EICAR")+len(eicarTail) &&
		bytes.HasPrefix(d, []byte(eicarHead)) && bytes.HasSuffix(d, []byte(eicarTail)) &&
		bytes.Equal(d[len(eicarHead):len(eicarHead)+5], []byte("EICAR"))
}

// checkContent fayl mazmuni va nomiga asoslangan evristikalar.
func checkContent(name string, data []byte) []Threat {
	ext := strings.ToLower(filepath.Ext(name))
	var out []Threat
	if isEICAR(data) {
		out = append(out, Threat{Name: "EICAR-Test-File", Severity: Malicious, Kind: KindRule})
	}
	if documentExts[ext] && isPE(data) {
		out = append(out, Threat{Name: "Heur.DisguisedExecutable", Severity: Suspicious, Kind: KindHeuristic})
	}
	if ext == ".lnk" && bytes.HasPrefix(data, lnkHeader) {
		if t, ok := checkShortcut(data); ok {
			out = append(out, t)
		}
	}
	return out
}

// checkShortcut .lnk yorliqlarida fleshka virusiga xos buyruqlarni qidiradi:
// masalan  cmd.exe /c start "" "x.vbs" & start explorer "Papka".
func checkShortcut(data []byte) (Threat, bool) {
	s := lowerASCII(data, true)
	has := func(p string) bool { return bytes.Contains(s, []byte(p)) }
	cmd := has("cmd.exe") || has("cmd /c")
	if !cmd && !has("powershell") && !has("mshta") {
		return Threat{}, false
	}
	payload := has(".vbs") || has(".vbe") || has(".js") || has(".jse") || has(".wsf") || has(".hta") || has(".exe") || has(".dll")
	chained := has("/c start") || has("&start") || has("& start") || has("/c \"start")
	switch {
	case has("powershell") && (has("-enc") || has("hidden") || has("downloadstring") || has("iex")):
		return Threat{Name: "Trojan.LNK.PowerShell", Severity: Malicious, Kind: KindHeuristic}, true
	case has("mshta") && (has("http:") || has("https:") || has("javascript:") || has("vbscript:")):
		return Threat{Name: "Trojan.LNK.Mshta", Severity: Malicious, Kind: KindHeuristic}, true
	case cmd && chained && payload:
		return Threat{Name: "Worm.LNK.ShortcutVirus", Severity: Malicious, Kind: KindHeuristic}, true
	}
	return Threat{}, false
}
