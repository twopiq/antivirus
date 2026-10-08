package quarantine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAddRestoreDelete(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(filepath.Join(dir, "q"))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "virus.exe")
	content := []byte("MZ zararli dastur")
	os.WriteFile(src, content, 0o444)

	it, err := q.Add(src, "Test.Virus")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("asl fayl o'chirilmadi")
	}
	stored, _ := os.ReadFile(filepath.Join(q.Dir, it.ID+".bin"))
	if bytes.Equal(stored, content) {
		t.Fatal("karantindagi fayl kodlanmagan")
	}
	items, _ := q.List()
	if len(items) != 1 || items[0].Threat != "Test.Virus" {
		t.Fatalf("ro'yxat: %+v", items)
	}
	dst, err := q.Restore("1", "")
	if err != nil || dst != src {
		t.Fatalf("tiklash: %v %s", err, dst)
	}
	got, _ := os.ReadFile(src)
	if !bytes.Equal(got, content) {
		t.Fatal("tiklangan fayl mazmuni farq qiladi")
	}
	if items, _ := q.List(); len(items) != 0 {
		t.Fatal("tiklangandan keyin karantin bo'sh emas")
	}

	if _, err := q.Add(src, "Test.Virus"); err != nil {
		t.Fatal(err)
	}
	if n, err := q.Clear(); err != nil || n != 1 {
		t.Fatalf("tozalash: %d %v", n, err)
	}
}
