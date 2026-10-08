package engine

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// builtinSignatures — dastur ichiga joylangan minimal baza. Asosiy baza
// "update" buyrug'i orqali MalwareBazaar (abuse.ch) dan yuklanadi.
const builtinSignatures = `# Qalqon ichki imzolari: sha256 [nomi]
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR-Test-File
`

// SignatureDB — SHA-256 xeshlar bazasi. Millionlab yozuvlarni kam xotira
// bilan saqlash uchun tartiblangan massiv va ikkilik qidiruvdan foydalanadi.
type SignatureDB struct {
	hashes [][32]byte
	names  map[[32]byte]string
}

// NewSignatureDB bo'sh bazani qaytaradi (ichki imzolar bilan).
func NewSignatureDB() *SignatureDB {
	db := &SignatureDB{names: map[[32]byte]string{}}
	_ = db.load(strings.NewReader(builtinSignatures))
	db.finish()
	return db
}

// LoadSignatureDB ichki imzolar va berilgan fayllardagi imzolarni yuklaydi.
// Mavjud bo'lmagan fayllar e'tiborsiz qoldiriladi.
func LoadSignatureDB(paths ...string) (*SignatureDB, error) {
	db := &SignatureDB{names: map[[32]byte]string{}}
	_ = db.load(strings.NewReader(builtinSignatures))
	for _, p := range paths {
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		err = db.load(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	db.finish()
	return db, nil
}

// ParseHashLine "sha256 [nomi]" ko'rinishidagi satrni tahlil qiladi.
// MalwareBazaar eksportidagi "sha256" yoki CSV ("...","sha256",...) satrlari ham qabul qilinadi.
func ParseHashLine(line string) (h [32]byte, name string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return h, "", false
	}
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '"'
	})
	if len(fields) == 0 {
		return h, "", false
	}
	idx := -1
	for i, f := range fields {
		if len(f) == 64 && isHex(f) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return h, "", false
	}
	if _, err := hex.Decode(h[:], []byte(strings.ToLower(fields[idx]))); err != nil {
		return h, "", false
	}
	if idx == 0 && len(fields) > 1 {
		name = strings.Join(fields[1:], " ")
	}
	return h, name, true
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (db *SignatureDB) load(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		h, name, ok := ParseHashLine(sc.Text())
		if !ok {
			continue
		}
		db.hashes = append(db.hashes, h)
		if name != "" {
			db.names[h] = name
		}
	}
	return sc.Err()
}

func (db *SignatureDB) finish() {
	sort.Slice(db.hashes, func(i, j int) bool { return bytes.Compare(db.hashes[i][:], db.hashes[j][:]) < 0 })
	out := db.hashes[:0]
	for i, h := range db.hashes {
		if i == 0 || h != db.hashes[i-1] {
			out = append(out, h)
		}
	}
	db.hashes = out
}

// Len bazadagi imzolar sonini qaytaradi.
func (db *SignatureDB) Len() int { return len(db.hashes) }

// Lookup xesh bazada bormi — tekshiradi va topilsa tahdid nomini qaytaradi.
func (db *SignatureDB) Lookup(h [32]byte) (string, bool) {
	i := sort.Search(len(db.hashes), func(i int) bool { return bytes.Compare(db.hashes[i][:], h[:]) >= 0 })
	if i < len(db.hashes) && db.hashes[i] == h {
		if n := db.names[h]; n != "" {
			return n, true
		}
		return "Malware.Hash." + hex.EncodeToString(h[:4]), true
	}
	return "", false
}

// MergeHashFile yangi xeshlarni (r) mavjud baza fayliga (path) qo'shadi va
// faylni qayta yozadi. Qo'shilgan yangi yozuvlar sonini qaytaradi.
func MergeHashFile(path string, r io.Reader, defaultName string) (added, total int, err error) {
	existing := map[[32]byte]string{}
	var order [][32]byte
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if h, name, ok := ParseHashLine(sc.Text()); ok {
				if _, dup := existing[h]; !dup {
					order = append(order, h)
				}
				existing[h] = name
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return 0, 0, err
		}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		h, name, ok := ParseHashLine(sc.Text())
		if !ok {
			continue
		}
		if _, dup := existing[h]; dup {
			continue
		}
		if name == "" {
			name = defaultName
		}
		existing[h] = name
		order = append(order, h)
		added++
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, 0, err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# Qalqon virus bazasi: sha256 [nomi]")
	for _, h := range order {
		if n := existing[h]; n != "" {
			fmt.Fprintf(w, "%x %s\n", h, n)
		} else {
			fmt.Fprintf(w, "%x\n", h)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return 0, 0, err
	}
	if err := f.Close(); err != nil {
		return 0, 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, 0, err
	}
	return added, len(order), nil
}
