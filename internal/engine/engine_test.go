package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// Faylga qo'shimcha ma'lumot qo'shilsa ham qoida ishlashi kerak.
	if ts := e.ScanBytes("x.txt", []byte("hello\n"+eicar+"\n")); len(ts) == 0 {
		t.Fatal("EICAR qoidasi ishlamadi")
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

func TestSignatureDB(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sig.txt")
	h1 := strings.Repeat("ab", 32)
	h2 := strings.Repeat("cd", 32)
	added, total, err := MergeHashFile(p, strings.NewReader("# comment\n"+h1+"\n"+strings.ToUpper(h2)+" Trojan.Test\n"+h1+"\n"), "")
	if err != nil || added != 2 || total != 2 {
		t.Fatalf("merge: %d %d %v", added, total, err)
	}
	added, total, _ = MergeHashFile(p, strings.NewReader(h2+"\n"+strings.Repeat("ef", 32)+"\n"), "")
	if added != 1 || total != 3 {
		t.Fatalf("ikkinchi merge: %d %d", added, total)
	}
	db, err := LoadSignatureDB(p, filepath.Join(dir, "yoq.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 4 { // 3 + EICAR
		t.Fatalf("baza hajmi %d", db.Len())
	}
	var h [32]byte
	for i := range h {
		h[i] = 0xcd
	}
	if n, ok := db.Lookup(h); !ok || n != "Trojan.Test" {
		t.Fatalf("lookup: %q %v", n, ok)
	}
	h[0] = 0
	if _, ok := db.Lookup(h); ok {
		t.Fatal("mavjud bo'lmagan xesh topildi")
	}
	// MalwareBazaar CSV formati.
	if _, _, ok := ParseHashLine(`"2024-01-01 00:00:00","` + h1 + `","md5","sha1"`); !ok {
		t.Fatal("CSV satri o'qilmadi")
	}
}
