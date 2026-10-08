package sigdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twopiq/antivirus/internal/bodysig"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func makeCVD(t *testing.T, gz bool, files map[string]string) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	payload := tarBuf.Bytes()
	if gz {
		var gzBuf bytes.Buffer
		zw := gzip.NewWriter(&gzBuf)
		zw.Write(payload)
		zw.Close()
		payload = gzBuf.Bytes()
	}
	hdr := fmt.Sprintf("ClamAV-VDB:08 Oct 2026 10-00 +0000:27000:%d:90:md5:dsig:builder:0", len(files))
	hdr += strings.Repeat(" ", 512-len(hdr))
	return append([]byte(hdr), payload...)
}

func hashes(data []byte) Hashes {
	m := md5.Sum(data)
	s1 := sha1.Sum(data)
	s2 := sha256.Sum256(data)
	return Hashes{MD5: m[:], SHA1: s1[:], SHA256: s2[:]}
}

func TestBuildAndLookup(t *testing.T) {
	root := t.TempDir()
	st := Store{Root: root}
	os.MkdirAll(st.SourcesDir(), 0o755)

	other := []byte("boshqa zararli fayl")
	oh := hashes(other)
	fpData := []byte("ishonchli fayl")
	fph := hashes(fpData)
	section := []byte("PE section bytes")
	sh := hashes(section)

	main := makeCVD(t, true, map[string]string{
		"main.hdb": "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n" +
			hex.EncodeToString(fph.MD5) + fmt.Sprintf(":%d:Win.Trojan.FP-1-0\n", len(fpData)) +
			hex.EncodeToString(oh.MD5) + ":999:Win.Trojan.WrongSize-1-0\n",
		"main.hsb": hex.EncodeToString(oh.SHA1) + ":*:Win.Trojan.Sha1Test-12345-0\n",
		"main.mdb": fmt.Sprintf("%d:%s:Win.Trojan.Section-777-1\n", len(section), hex.EncodeToString(sh.MD5)),
		"main.ndb": "Win.Trojan.Body-1-0:0:*:4d414c57415245434f5245\nWin.Trojan.Ignored-2-0:0:*:49474e4f5245444d45\nUnsupported-3:0:*:!(4141)42424242\n",
		"main.ldb": "ignored logical sig",
		"main.hdu": "44d88612fea8a8f36de82e1278abb02f:68:PUA.Test\n",
	})
	daily := makeCVD(t, false, map[string]string{
		"daily.ign2": "Win.Trojan.Ignored-2-0\n",
		"daily.fp":   hex.EncodeToString(fph.MD5) + fmt.Sprintf(":%d:FP-fix\n", len(fpData)),
	})
	os.WriteFile(filepath.Join(st.SourcesDir(), "main.cvd"), main, 0o644)
	os.WriteFile(filepath.Join(st.SourcesDir(), "daily.cld"), daily, 0o644)
	bazaarHash := strings.Repeat("ab", 32)
	os.WriteFile(filepath.Join(st.SourcesDir(), "bazaar.txt"), []byte("# MalwareBazaar\n"+bazaarHash+"\n"), 0o644)
	os.WriteFile(filepath.Join(root, "signatures.txt"), []byte(strings.Repeat("cd", 32)+" Legacy.Test\n"), 0o644)

	stats, err := st.Rebuild(nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Body != 1 || stats.BodySkipped != 2 || stats.Sections != 1 || stats.Allow != 1 {
		t.Fatalf("statistika: %+v", stats)
	}
	db, err := st.Open()
	if err != nil || db == nil {
		t.Fatalf("ochish: %v", err)
	}
	defer db.Close()

	if n, ok := db.LookupFile(hashes([]byte(eicar)), int64(len(eicar))); !ok || n != "Eicar-Test-Signature" {
		t.Fatalf("EICAR md5: %q %v", n, ok)
	}
	if n, ok := db.LookupFile(oh, int64(len(other))); !ok || n != "Win.Trojan.Sha1Test" {
		t.Fatalf("sha1 '*' hajm: %q %v", n, ok)
	}
	if !db.Allowed(fph, int64(len(fpData))) {
		t.Fatal(".fp ishlamadi")
	}
	if n, ok := db.LookupSection(sh, uint32(len(section))); !ok || n != "Win.Trojan.Section" {
		t.Fatalf("bo'lim: %q %v", n, ok)
	}
	if _, ok := db.LookupSection(sh, uint32(len(section)+1)); ok {
		t.Fatal("bo'lim hajmi tekshirilmadi")
	}
	var bh [32]byte
	hex.Decode(bh[:], []byte(bazaarHash))
	if _, ok := db.LookupFile(Hashes{SHA256: bh[:]}, 5); !ok {
		t.Fatal("MalwareBazaar xeshi topilmadi")
	}
	var lh [32]byte
	hex.Decode(lh[:], []byte(strings.Repeat("cd", 32)))
	if n, ok := db.LookupFile(Hashes{SHA256: lh[:]}, 5); !ok || n != "Legacy.Test" {
		t.Fatalf("eski baza ko'chirilmadi: %q %v", n, ok)
	}
	if got := db.Body.Scan([]byte("xxMALWARECOREyy"), bodysig.FileInfo{EP: -1}); len(got) != 1 || got[0] != "Win.Trojan.Body-1-0" {
		t.Fatalf("tana imzosi: %v", got)
	}
	if got := db.Body.Scan([]byte("IGNOREDME"), bodysig.FileInfo{EP: -1}); len(got) != 0 {
		t.Fatalf("ign2 ishlamadi: %v", got)
	}
	if db.Count() < 6 {
		t.Fatalf("soni: %d", db.Count())
	}

	// Qayta kompilyatsiya — eski versiya o'chiriladi.
	old := st.CurrentVersion()
	os.MkdirAll(filepath.Join(root, "db", "old-version"), 0o755)
	if _, err := st.Rebuild(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "db", "old-version")); !os.IsNotExist(err) {
		t.Fatal("eski versiya o'chirilmadi")
	}
	_ = old
}

func TestAppendList(t *testing.T) {
	st := Store{Root: t.TempDir()}
	h := strings.Repeat("12", 32)
	n, err := st.AppendList("allow.txt", []string{h + " test", h, "yaroqsiz"})
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	n, _ = st.AppendList("allow.txt", []string{strings.ToUpper(h)})
	if n != 0 {
		t.Fatal("takror qo'shildi")
	}
}

func TestFamily(t *testing.T) {
	for in, want := range map[string]string{
		"Win.Trojan.Agent-6340983-0": "Win.Trojan.Agent",
		"Eicar-Test-Signature":       "Eicar-Test-Signature",
		"Doc.Dropper.Emotet-9-1":     "Doc.Dropper.Emotet",
		"Win.Exploit.CVE_2012-0158":  "Win.Exploit.CVE_2012-0158",
	} {
		if got := family(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
	if FormatCount(1234567) != "1 234 567" || FormatCount(12) != "12" {
		t.Error(FormatCount(1234567))
	}
}
