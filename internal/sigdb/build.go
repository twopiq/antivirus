package sigdb

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/twopiq/antivirus/internal/bodysig"
)

// Jadval nomlari.
const (
	tMD5        = "md5"
	tSHA1       = "sha1"
	tSHA256     = "sha256"
	tSecMD5     = "sec-md5"
	tSecSHA1    = "sec-sha1"
	tSecSHA256  = "sec-sha256"
	tAllowMD5   = "allow-md5"
	tAllowSHA1  = "allow-sha1"
	tAllowSHA25 = "allow-sha256"
)

var tableNames = []string{tMD5, tSHA1, tSHA256, tSecMD5, tSecSHA1, tSecSHA256, tAllowMD5, tAllowSHA1, tAllowSHA25}

func hashTable(prefix string, n int) string {
	suffix := map[int]string{16: "md5", 20: "sha1", 32: "sha256"}[n]
	if prefix == "" {
		return suffix
	}
	return prefix + "-" + suffix
}

// Stats — kompilyatsiya statistikasi.
type Stats struct {
	Hashes      int
	Sections    int
	Body        int
	BodySkipped int
	Allow       int
	Sources     []string
}

func (s Stats) Total() int { return s.Hashes + s.Sections + s.Body }

type builder struct {
	tables   map[string]*tableBuilder
	names    map[string]uint32
	nameList []string
	ndb      []string
	ign      map[string]bool
	stats    Stats
}

func newBuilder() *builder {
	b := &builder{tables: map[string]*tableBuilder{}, names: map[string]uint32{}, ign: map[string]bool{}}
	for _, n := range tableNames {
		hl := map[string]int{"md5": 16, "sha1": 20, "sha256": 32}[n[strings.LastIndex(n, "-")+1:]]
		b.tables[n] = &tableBuilder{hashLen: hl}
	}
	return b
}

func (b *builder) nameIdx(name string) uint32 {
	name = family(name)
	if i, ok := b.names[name]; ok {
		return i
	}
	i := uint32(len(b.nameList))
	b.names[name] = i
	b.nameList = append(b.nameList, name)
	return i
}

func lines(r io.Reader, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if !isEmptyLine(sc.Bytes()) {
			fn(sc.Text())
		}
	}
	return sc.Err()
}

func extOf(name string) string { return strings.ToLower(filepath.Ext(name)) }

// addIgnores .ign/.ign2 fayllaridagi o'chirilgan imzo nomlarini yig'adi.
func (b *builder) addIgnores(r io.Reader) error {
	return lines(r, func(l string) {
		f := strings.Split(strings.TrimSpace(l), ":")
		// .ign2: "Nomi[:md5]"; eski .ign: "baza:satr:Nomi".
		if len(f) >= 3 {
			b.ign[f[2]] = true
		} else {
			b.ign[f[0]] = true
		}
	})
}

// addMember bitta imzo faylini (kengaytmasi bo'yicha) qayta ishlaydi.
func (b *builder) addMember(name string, r io.Reader) error {
	switch extOf(name) {
	case ".hdb", ".hsb":
		return lines(r, func(l string) {
			if h, size, n, ok := hashLine(l, false); ok && !b.ign[n] {
				b.tables[hashTable("", len(h))].add(h, size, b.nameIdx(n))
				b.stats.Hashes++
			}
		})
	case ".mdb", ".msb":
		return lines(r, func(l string) {
			if h, size, n, ok := hashLine(l, true); ok && !b.ign[n] && size != AnySize {
				b.tables[hashTable("sec", len(h))].add(h, size, b.nameIdx(n))
				b.stats.Sections++
			}
		})
	case ".fp", ".sfp":
		return lines(r, func(l string) {
			if h, size, _, ok := hashLine(l, false); ok {
				b.tables[hashTable("allow", len(h))].add(h, size, 0)
				b.stats.Allow++
			}
		})
	case ".ndb":
		return lines(r, func(l string) {
			s, err := bodysig.ParseLine(l)
			if err != nil || b.ign[s.Name] {
				b.stats.BodySkipped++
				return
			}
			b.ndb = append(b.ndb, strings.TrimSpace(l))
			b.stats.Body++
		})
	}
	return nil
}

// addList oddiy xeshlar ro'yxatini qo'shadi (allow=true — ishonchli fayllar).
func (b *builder) addList(r io.Reader, defName string, allow bool) error {
	return lines(r, func(l string) {
		h, n, ok := ParseListLine(l)
		if !ok {
			return
		}
		if allow {
			b.tables[hashTable("allow", len(h))].add(h, AnySize, 0)
			b.stats.Allow++
			return
		}
		if n == "" {
			n = defName
		}
		b.tables[hashTable("", len(h))].add(h, AnySize, b.nameIdx(n))
		b.stats.Hashes++
	})
}

func isCVD(name string) bool {
	switch extOf(name) {
	case ".cvd", ".cld", ".cud":
		return true
	}
	return false
}

// build manba fayllardan bazani kompilyatsiya qilib, outDir ga yozadi.
func build(outDir string, sources []string, progress func(string)) (Stats, error) {
	b := newBuilder()
	// 1-o'tish: o'chirilgan (ign) imzolar ro'yxatini yig'ish.
	for _, src := range sources {
		switch {
		case isCVD(src):
			f, err := os.Open(src)
			if err != nil {
				return b.stats, err
			}
			_, err = walkCVD(f, func(name string, r io.Reader) error {
				if e := extOf(name); e == ".ign" || e == ".ign2" {
					return b.addIgnores(r)
				}
				return nil
			})
			f.Close()
			if err != nil {
				return b.stats, fmt.Errorf("%s: %w", filepath.Base(src), err)
			}
		case extOf(src) == ".ign" || extOf(src) == ".ign2":
			f, err := os.Open(src)
			if err != nil {
				return b.stats, err
			}
			err = b.addIgnores(f)
			f.Close()
			if err != nil {
				return b.stats, err
			}
		}
	}
	// 2-o'tish: imzolar.
	for _, src := range sources {
		if progress != nil {
			progress(filepath.Base(src))
		}
		f, err := os.Open(src)
		if err != nil {
			return b.stats, err
		}
		base := strings.ToLower(filepath.Base(src))
		switch {
		case isCVD(src):
			var h CVDHeader
			h, err = walkCVD(f, b.addMember)
			b.stats.Sources = append(b.stats.Sources, fmt.Sprintf("%s v%d", base, h.Version))
		case base == "allow.txt":
			err = b.addList(f, "", true)
		case extOf(src) == ".txt" || extOf(src) == ".csv":
			err = b.addList(f, "Malware.Generic", false)
			b.stats.Sources = append(b.stats.Sources, base)
		default:
			err = b.addMember(src, f)
			b.stats.Sources = append(b.stats.Sources, base)
		}
		f.Close()
		if err != nil {
			return b.stats, fmt.Errorf("%s: %w", filepath.Base(src), err)
		}
	}
	return b.stats, b.write(outDir)
}

func (b *builder) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, t := range b.tables {
		if t.count() == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name+".tbl"), t.sorted(), 0o644); err != nil {
			return err
		}
		t.buf = nil
	}
	if err := os.WriteFile(filepath.Join(dir, "names.txt"), []byte(strings.Join(b.nameList, "\n")), 0o644); err != nil {
		return err
	}
	sort.Strings(b.ndb)
	if err := os.WriteFile(filepath.Join(dir, "body.ndb"), []byte(strings.Join(b.ndb, "\n")), 0o644); err != nil {
		return err
	}
	info := fmt.Sprintf("hashes=%d\nsections=%d\nbody=%d\nallow=%d\nsources=%s\n", b.stats.Hashes, b.stats.Sections, b.stats.Body, b.stats.Allow, strings.Join(b.stats.Sources, ", "))
	return os.WriteFile(filepath.Join(dir, "info.txt"), []byte(info), 0o644)
}
