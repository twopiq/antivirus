// Package sigdb Qalqon virus bazasi: ClamAV (.cvd, .hdb, .hsb, .mdb, .ndb, ...),
// MalwareBazaar va foydalanuvchi ro'yxatlarini ixcham jadvallarga kompilyatsiya
// qiladi va ularni xotiraga akslantirib (mmap) tez qidiradi.
package sigdb

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/bodysig"
)

// DB — ochilgan (kompilyatsiya qilingan) baza.
type DB struct {
	Version string
	Dir     string
	tables  map[string]*table
	names   []string
	Body    *bodysig.Matcher
	closers []func() error
	Info    map[string]string
}

// Open kompilyatsiya qilingan baza papkasini ochadi.
func Open(dir string) (*DB, error) {
	db := &DB{Dir: dir, Version: filepath.Base(dir), tables: map[string]*table{}, Body: bodysig.NewMatcher(), Info: map[string]string{}}
	for _, n := range tableNames {
		p := filepath.Join(dir, n+".tbl")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		data, closer, err := mapFile(p)
		if err != nil {
			db.Close()
			return nil, err
		}
		db.closers = append(db.closers, closer)
		hl := map[string]int{"md5": 16, "sha1": 20, "sha256": 32}[n[strings.LastIndex(n, "-")+1:]]
		db.tables[n] = &table{hashLen: hl, data: data}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "names.txt")); err == nil && len(b) > 0 {
		db.names = strings.Split(string(b), "\n")
	}
	if f, err := os.Open(filepath.Join(dir, "body.ndb")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for sc.Scan() {
			if s, err := bodysig.ParseLine(sc.Text()); err == nil {
				db.Body.Add(s)
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile(filepath.Join(dir, "info.txt")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				db.Info[k] = v
			}
		}
	}
	return db, nil
}

// Close xotiradagi akslantirishlarni bo'shatadi.
func (db *DB) Close() {
	if db == nil {
		return
	}
	for _, c := range db.closers {
		_ = c()
	}
	db.closers = nil
	db.tables = map[string]*table{}
}

func (db *DB) name(i uint32) string {
	if int(i) < len(db.names) {
		return db.names[i]
	}
	return "Malware.Generic"
}

// Count bazadagi imzolar soni.
func (db *DB) Count() int {
	if db == nil {
		return 0
	}
	n := db.Body.Len()
	for k, t := range db.tables {
		if !strings.HasPrefix(k, "allow") {
			n += t.count()
		}
	}
	return n
}

// Hashes fayl xeshlari.
type Hashes struct {
	MD5, SHA1, SHA256 []byte
}

// LookupFile fayl xeshlari bo'yicha qidiradi.
func (db *DB) LookupFile(h Hashes, size int64) (string, bool) {
	if db == nil {
		return "", false
	}
	sz := uint32(size)
	if size >= AnySize {
		sz = AnySize - 1
	}
	for _, p := range []struct {
		t string
		h []byte
	}{{tSHA256, h.SHA256}, {tMD5, h.MD5}, {tSHA1, h.SHA1}} {
		if i, ok := db.tables[p.t].lookup(p.h, sz); ok {
			return db.name(i), true
		}
	}
	return "", false
}

// LookupSection PE bo'limi xeshi bo'yicha qidiradi.
func (db *DB) LookupSection(h Hashes, size uint32) (string, bool) {
	if db == nil {
		return "", false
	}
	for _, p := range []struct {
		t string
		h []byte
	}{{tSecMD5, h.MD5}, {tSecSHA256, h.SHA256}, {tSecSHA1, h.SHA1}} {
		if i, ok := db.tables[p.t].lookup(p.h, size); ok {
			return db.name(i), true
		}
	}
	return "", false
}

// Allowed fayl ishonchli ro'yxatda (false positive) bormi.
func (db *DB) Allowed(h Hashes, size int64) bool {
	if db == nil {
		return false
	}
	sz := uint32(size)
	for _, p := range []struct {
		t string
		h []byte
	}{{tAllowSHA25, h.SHA256}, {tAllowMD5, h.MD5}, {tAllowSHA1, h.SHA1}} {
		if _, ok := db.tables[p.t].lookup(p.h, sz); ok {
			return true
		}
	}
	return false
}

// NeedSHA1 bazada SHA-1 imzolar bormi (aks holda hisoblash shart emas).
func (db *DB) NeedSHA1() bool {
	return db != nil && (db.tables[tSHA1].count() > 0 || db.tables[tAllowSHA1].count() > 0)
}

// HasSections bazada PE bo'limi imzolari bormi.
func (db *DB) HasSections() bool {
	return db != nil && (db.tables[tSecMD5].count()+db.tables[tSecSHA1].count()+db.tables[tSecSHA256].count()) > 0
}

// Store — ma'lumotlar papkasidagi manbalar va kompilyatsiya qilingan bazalar.
//
//	<root>/sources/   — manba fayllar (main.cvd, daily.cvd, bazaar.txt, custom.txt, allow.txt, ...)
//	<root>/db/<ver>/  — kompilyatsiya qilingan baza
//	<root>/db/current — joriy versiya nomi
type Store struct{ Root string }

// SourcesDir manba fayllar papkasi.
func (s Store) SourcesDir() string { return filepath.Join(s.Root, "sources") }

func (s Store) dbDir() string { return filepath.Join(s.Root, "db") }

// CurrentVersion joriy baza versiyasi ("" — hali yo'q).
func (s Store) CurrentVersion() string {
	b, err := os.ReadFile(filepath.Join(s.dbDir(), "current"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Open joriy bazani ochadi. Baza hali kompilyatsiya qilinmagan bo'lsa nil qaytaradi.
func (s Store) Open() (*DB, error) {
	v := s.CurrentVersion()
	if v == "" {
		return nil, nil
	}
	return Open(filepath.Join(s.dbDir(), v))
}

// Sources manba fayllar ro'yxati (barqaror tartibda).
func (s Store) Sources() []string {
	ents, _ := os.ReadDir(s.SourcesDir())
	var out []string
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, filepath.Join(s.SourcesDir(), e.Name()))
	}
	sort.Strings(out)
	return out
}

// MigrateLegacy 1-versiyadagi signatures.txt faylini manbalarga ko'chiradi.
func (s Store) MigrateLegacy() {
	old := filepath.Join(s.Root, "signatures.txt")
	if _, err := os.Stat(old); err != nil {
		return
	}
	_ = os.MkdirAll(s.SourcesDir(), 0o755)
	_ = os.Rename(old, filepath.Join(s.SourcesDir(), "legacy.txt"))
}

// Rebuild barcha manbalardan yangi bazani kompilyatsiya qiladi va uni joriy qiladi.
func (s Store) Rebuild(progress func(string)) (Stats, error) {
	s.MigrateLegacy()
	srcs := s.Sources()
	if len(srcs) == 0 {
		return Stats{}, errors.New("manba fayllar yo'q")
	}
	// Har bir kompilyatsiya yangi papkaga yoziladi: Windows'da ochiq (mmap) baza
	// fayllarini qayta yozib bo'lmaydi, masalan real vaqt himoyasi ishlab turganda.
	ver := time.Now().Format("20060102-150405")
	out := filepath.Join(s.dbDir(), ver)
	for i := 2; ; i++ {
		if _, err := os.Stat(out); os.IsNotExist(err) {
			break
		}
		ver = fmt.Sprintf("%s-%d", time.Now().Format("20060102-150405"), i)
		out = filepath.Join(s.dbDir(), ver)
	}
	st, err := build(out, srcs, progress)
	if err != nil {
		os.RemoveAll(out)
		return st, err
	}
	tmp := filepath.Join(s.dbDir(), "current.tmp")
	if err := os.WriteFile(tmp, []byte(ver), 0o644); err != nil {
		return st, err
	}
	if err := os.Rename(tmp, filepath.Join(s.dbDir(), "current")); err != nil {
		return st, err
	}
	s.cleanup(ver)
	return st, nil
}

// cleanup eski baza versiyalarini o'chiradi (ishlatilayotganlari qoladi).
func (s Store) cleanup(keep string) {
	ents, _ := os.ReadDir(s.dbDir())
	for _, e := range ents {
		if e.IsDir() && e.Name() != keep {
			_ = os.RemoveAll(filepath.Join(s.dbDir(), e.Name()))
		}
	}
}

// AppendList xeshlarni manba ro'yxatiga (masalan custom.txt yoki allow.txt) qo'shadi.
// Takrorlanganlari qo'shilmaydi. Qo'shilganlar sonini qaytaradi.
func (s Store) AppendList(file string, entries []string) (int, error) {
	p := filepath.Join(s.SourcesDir(), file)
	if err := os.MkdirAll(s.SourcesDir(), 0o755); err != nil {
		return 0, err
	}
	have := map[string]bool{}
	if b, err := os.ReadFile(p); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if h, _, ok := ParseListLine(l); ok {
				have[string(h)] = true
			}
		}
	}
	var buf bytes.Buffer
	for _, e := range entries {
		h, _, ok := ParseListLine(e)
		if !ok || have[string(h)] {
			continue
		}
		have[string(h)] = true
		buf.WriteString(strings.TrimSpace(e) + "\n")
	}
	if buf.Len() == 0 {
		return 0, nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	_, err = f.Write(buf.Bytes())
	return strings.Count(buf.String(), "\n"), err
}

// FormatCount sonni o'qishga qulay ko'rinishda chiqaradi: 1234567 -> "1 234 567".
func FormatCount(n int) string {
	s := strconv.Itoa(n)
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, s[i])
	}
	return string(out)
}
