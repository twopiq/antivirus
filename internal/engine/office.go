package engine

import (
	"bytes"
	"math/bits"
	"strings"
)

const maxVBASource = 8 << 20

// decompressVBA MS-OVBA siqilgan konteynerini ochadi (2.4.1 bo'lim).
func decompressVBA(c []byte) ([]byte, bool) {
	if len(c) < 3 || c[0] != 0x01 {
		return nil, false
	}
	var out []byte
	pos := 1
	for pos+2 <= len(c) && len(out) < maxVBASource {
		hdr := uint16(c[pos]) | uint16(c[pos+1])<<8
		if (hdr>>12)&0x7 != 0x3 {
			break
		}
		size := int(hdr&0x0FFF) + 3
		chunkEnd := min(pos+size, len(c))
		pos += 2
		chunkStart := len(out)
		if hdr&0x8000 == 0 {
			end := min(pos+4096, len(c))
			out = append(out, c[pos:end]...)
			pos = end
			continue
		}
		for pos < chunkEnd {
			flags := c[pos]
			pos++
			for bit := 0; bit < 8 && pos < chunkEnd; bit++ {
				if flags&(1<<bit) == 0 {
					out = append(out, c[pos])
					pos++
					continue
				}
				if pos+1 >= chunkEnd {
					return out, len(out) > 0
				}
				tok := uint16(c[pos]) | uint16(c[pos+1])<<8
				pos += 2
				diff := len(out) - chunkStart
				bitCount := max(bits.Len(uint(max(diff-1, 0))), 4)
				lengthMask := uint16(0xFFFF) >> bitCount
				offset := int(tok>>(16-bitCount)) + 1
				length := int(tok&lengthMask) + 3
				src := len(out) - offset
				if src < chunkStart {
					return out, len(out) > 0
				}
				for k := 0; k < length; k++ {
					out = append(out, out[src+k])
				}
			}
		}
		pos = chunkEnd
	}
	return out, len(out) > 0
}

// extractVBA OLE/vbaProject.bin ma'lumotlaridan makros matnlarini ajratadi.
// OLE tuzilmasini to'liq tahlil qilmasdan, siqilgan modul boshlanishini
// ("Attribute VB_Name" siqilgan ko'rinishi) qidiradi — oletools usuli.
func extractVBA(data []byte) string {
	var sb strings.Builder
	marker := []byte("\x00Attribut")
	for i := 0; ; {
		j := bytes.Index(data[i:], marker)
		if j < 0 {
			break
		}
		at := i + j
		i = at + len(marker)
		if at < 3 || i >= len(data) || data[i] == 'e' {
			continue
		}
		if src, ok := decompressVBA(data[at-3:]); ok && bytes.Contains(src, []byte("Attribute")) {
			sb.Write(src)
			sb.WriteByte('\n')
			if sb.Len() > maxVBASource {
				break
			}
		}
	}
	return sb.String()
}

var (
	vbaAutoExec = []string{"autoopen", "auto_open", "document_open", "workbook_open", "autoexec", "autoclose", "auto_close", "document_close", "workbook_beforeclose", "document_beforeclose", "workbook_activate", "documentopen"}
	vbaDownload = []string{"urldownloadtofile", "msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "msxml2.serverxmlhttp", "internetexplorer.application", "net.webclient", "downloadfile", "bitsadmin", "certutil"}
	vbaExec     = []string{"shell(", "shell ", "wscript.shell", "shell.application", "shellexecute", "createprocess", "powershell", "cmd /c", "cmd.exe", "mshta", "regsvr32", "rundll32", "winmgmts:", "win32_process", "callbyname", "executeexcel4macro", "macroscript"}
	vbaWrite    = []string{"adodb.stream", "savetofile", "put #", "createtextfile", "kill "}
)

func countAny(s string, words []string) int {
	n := 0
	for _, w := range words {
		if strings.Contains(s, w) {
			n++
		}
	}
	return n
}

// analyzeVBA makros matnini tahlil qiladi.
func analyzeVBA(src string) []Threat {
	if src == "" {
		return nil
	}
	s := strings.ToLower(src)
	auto := countAny(s, vbaAutoExec) > 0
	dl := countAny(s, vbaDownload) > 0
	ex := countAny(s, vbaExec) > 0
	wr := countAny(s, vbaWrite) > 0
	obf := strings.Count(s, "chr(")+strings.Count(s, "chrw(")+strings.Count(s, "chrb(") > 40 || strings.Contains(s, "strreverse")
	switch {
	case auto && dl && (ex || wr):
		return []Threat{{Name: "Trojan.Macro.Downloader", Severity: Malicious, Kind: KindHeuristic}}
	case auto && ex && (obf || wr):
		return []Threat{{Name: "Trojan.Macro.Dropper", Severity: Malicious, Kind: KindHeuristic}}
	case auto && (ex || dl):
		return []Threat{{Name: "Heur.Macro.AutoExec", Severity: Suspicious, Kind: KindHeuristic}}
	case dl && ex:
		return []Threat{{Name: "Heur.Macro.Downloader", Severity: Suspicious, Kind: KindHeuristic}}
	}
	return nil
}

var ole2Magic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Equation Editor (CVE-2017-11882) CLSID 0002CE02-0000-0000-C000-000000000046.
var equationCLSID = []byte{0x02, 0xCE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// checkOLE2 eski Office hujjatlari (.doc, .xls, .ppt) va vbaProject.bin.
func checkOLE2(data []byte) []Threat {
	out := analyzeVBA(extractVBA(data))
	if bytes.Contains(data, equationCLSID) || bytes.Contains(bytes.ToLower(data), []byte("equation.3")) {
		out = append(out, Threat{Name: "Exploit.OLE.EquationEditor", Severity: Suspicious, Kind: KindHeuristic})
	}
	return out
}

// checkOOXMLPart yangi Office hujjatlari (zip) ichidagi alohida qismlarni tekshiradi.
func checkOOXMLPart(name string, data []byte) []Threat {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, "vbaproject.bin"):
		return analyzeVBA(extractVBA(data))
	case strings.Contains(n, "macrosheets/"):
		return []Threat{{Name: "Heur.Macro.Excel4", Severity: Suspicious, Kind: KindHeuristic}}
	case strings.HasSuffix(n, ".rels"):
		s := strings.ToLower(string(data))
		if strings.Contains(s, "ms-msdt:") || strings.Contains(s, "search-ms:") {
			return []Threat{{Name: "Exploit.Office.Follina", Severity: Malicious, Kind: KindHeuristic}}
		}
		if strings.Contains(s, `targetmode="external"`) && (strings.Contains(s, "attachedtemplate") || strings.Contains(s, "/oleobject")) &&
			(strings.Contains(s, "http://") || strings.Contains(s, "https://") || strings.Contains(s, `\\`)) {
			return []Threat{{Name: "Exploit.Office.RemoteTemplate", Severity: Suspicious, Kind: KindHeuristic}}
		}
	}
	return nil
}

// checkPDF PDF fayllarda avtomatik ishga tushadigan JavaScript va /Launch amallari.
func checkPDF(data []byte) []Threat {
	s := bytes.ToLower(data)
	has := func(p string) bool { return bytes.Contains(s, []byte(p)) }
	var out []Threat
	if has("/launch") && (has(".exe") || has("cmd") || has("powershell") || has(".bat") || has(".vbs")) {
		out = append(out, Threat{Name: "Heur.PDF.Launch", Severity: Suspicious, Kind: KindHeuristic})
	}
	if (has("/javascript") || has("/js ") || has("/js(") || has("/js<")) && (has("/openaction") || has("/aa ") || has("/aa<")) {
		out = append(out, Threat{Name: "Heur.PDF.AutoJavaScript", Severity: Suspicious, Kind: KindHeuristic})
	}
	if has("/embeddedfile") && (has(".exe)") || has(".scr)") || has(".vbs)") || has(".js)") || has(".hta)") || has(".bat)")) {
		out = append(out, Threat{Name: "Heur.PDF.EmbeddedExecutable", Severity: Suspicious, Kind: KindHeuristic})
	}
	return out
}

// checkRTF RTF hujjatlardagi exploit belgilarini qidiradi.
func checkRTF(data []byte) []Threat {
	s := bytes.ToLower(data)
	if !bytes.Contains(s, []byte(`\objdata`)) && !bytes.Contains(s, []byte(`\objdat`)) {
		return nil
	}
	if bytes.Contains(s, []byte("equation.3")) || bytes.Contains(s, []byte("0002ce02")) || bytes.Contains(s, []byte("02ce020000000000c000000000000046")) {
		return []Threat{{Name: "Exploit.RTF.EquationEditor", Severity: Malicious, Kind: KindHeuristic}}
	}
	if bytes.Contains(s, []byte(`\objupdate`)) {
		return []Threat{{Name: "Heur.RTF.AutoUpdateObject", Severity: Suspicious, Kind: KindHeuristic}}
	}
	return nil
}
