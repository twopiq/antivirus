// Package engine — Qalqon antivirusining skanerlash dvigateli: xesh imzolari,
// mazmun qoidalari, evristikalar va ZIP arxivlar ichini tekshirish.
package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind — tahdid qanday aniqlangani.
type Kind string

const (
	KindHash      Kind = "imzo"
	KindRule      Kind = "qoida"
	KindHeuristic Kind = "evristika"
)

// Threat — topilgan tahdid.
type Threat struct {
	Path     string   // diskdagi fayl
	Inner    string   // arxiv ichidagi fayl (bo'lsa)
	Name     string   // tahdid nomi
	Severity Severity // daraja
	Kind     Kind     // aniqlash usuli
	SHA256   string
}

// Display tahdid joylashuvini foydalanuvchiga ko'rsatish uchun qaytaradi.
func (t Threat) Display() string {
	if t.Inner != "" {
		return t.Path + " > " + t.Inner
	}
	return t.Path
}

// Engine — skaner.
type Engine struct {
	DB *SignatureDB
	// MaxSize — mazmuni tekshiriladigan eng katta fayl hajmi (bayt).
	MaxSize int64
	// MaxArchiveEntries — ZIP ichida tekshiriladigan fayllar soni chegarasi.
	MaxArchiveEntries int
}

// New yangi skaner yaratadi.
func New(db *SignatureDB) *Engine {
	if db == nil {
		db = NewSignatureDB()
	}
	return &Engine{DB: db, MaxSize: 50 << 20, MaxArchiveEntries: 2000}
}

// ScanBytes xotiradagi ma'lumotni (name nomli fayl sifatida) tekshiradi.
func (e *Engine) ScanBytes(name string, data []byte) []Threat {
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	var out []Threat
	if n, ok := e.DB.Lookup(sum); ok {
		out = append(out, Threat{Name: n, Severity: Malicious, Kind: KindHash})
	}
	out = append(out, matchRules(name, data)...)
	out = append(out, checkContent(name, data)...)
	out = append(out, checkName(name)...)
	for i := range out {
		out[i].SHA256 = hexsum
	}
	return dedupe(out)
}

// ScanFile bitta faylni tekshiradi. Bir faylda bir nechta tahdid bo'lishi mumkin.
func (e *Engine) ScanFile(path string) ([]Threat, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil
	}
	if st.Size() > e.MaxSize {
		ts := checkName(path)
		for i := range ts {
			ts[i].Path = path
		}
		return ts, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	threats := e.ScanBytes(path, data)
	if isZip(path, data) {
		threats = append(threats, e.scanZip(data)...)
	}
	for i := range threats {
		threats[i].Path = path
	}
	return threats, nil
}

func isZip(path string, data []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return (ext == ".zip" || ext == ".jar") && bytes.HasPrefix(data, []byte("PK\x03\x04"))
}

func (e *Engine) scanZip(data []byte) []Threat {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []Threat
	for i, f := range zr.File {
		if i >= e.MaxArchiveEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		var ts []Threat
		if int64(f.UncompressedSize64) > e.MaxSize || f.Flags&0x1 != 0 { // juda katta yoki shifrlangan
			ts = checkName(f.Name)
		} else {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			buf, err := io.ReadAll(io.LimitReader(rc, e.MaxSize))
			rc.Close()
			if err != nil {
				continue
			}
			ts = e.ScanBytes(f.Name, buf)
		}
		for _, t := range ts {
			t.Inner = f.Name
			out = append(out, t)
		}
	}
	return out
}

func dedupe(ts []Threat) []Threat {
	seen := map[string]bool{}
	out := ts[:0]
	for _, t := range ts {
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		out = append(out, t)
	}
	return out
}

// Progress — skanerlash jarayoni haqida ma'lumot.
type Progress struct {
	Files   int64
	Threats int64
	Errors  int64
	Current string
}

// Options — skanerlash sozlamalari.
type Options struct {
	Workers int
	// Exclude — tekshirilmaydigan papkalar (prefiks bo'yicha, registrga sezgir emas).
	Exclude []string
	// OnProgress har ~200ms da chaqiriladi (ixtiyoriy).
	OnProgress func(Progress)
	// OnThreat tahdid topilganda darhol chaqiriladi (ixtiyoriy).
	OnThreat func(Threat)
}

// Result — skanerlash natijasi.
type Result struct {
	Threats  []Threat
	Files    int64
	Errors   int64
	Duration time.Duration
	Canceled bool
}

// skipDirNames — tekshirish shart bo'lmagan tizim papkalari.
var skipDirNames = map[string]bool{
	"system volume information": true,
	"winsxs":                    true,
	"$windows.~ws":              true,
	"$windows.~bt":              true,
}

// ScanPaths berilgan fayl va papkalarni bir nechta oqimda tekshiradi.
func (e *Engine) ScanPaths(ctx context.Context, paths []string, opt Options) *Result {
	start := time.Now()
	workers := opt.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
	}
	excl := make([]string, 0, len(opt.Exclude))
	for _, x := range opt.Exclude {
		if x != "" {
			excl = append(excl, strings.ToLower(filepath.Clean(x)))
		}
	}
	excluded := func(p string) bool {
		lp := strings.ToLower(p)
		for _, x := range excl {
			if lp == x || strings.HasPrefix(lp, x+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	var (
		res     Result
		mu      sync.Mutex
		files   atomic.Int64
		errs    atomic.Int64
		threats atomic.Int64
		current atomic.Value
	)
	current.Store("")
	jobs := make(chan string, 256)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				current.Store(p)
				ts, err := e.ScanFile(p)
				files.Add(1)
				if err != nil {
					errs.Add(1)
					continue
				}
				if len(ts) == 0 {
					continue
				}
				threats.Add(int64(len(ts)))
				mu.Lock()
				res.Threats = append(res.Threats, ts...)
				mu.Unlock()
				if opt.OnThreat != nil {
					for _, t := range ts {
						opt.OnThreat(t)
					}
				}
			}
		}()
	}

	done := make(chan struct{})
	if opt.OnProgress != nil {
		go func() {
			tk := time.NewTicker(200 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					opt.OnProgress(Progress{Files: files.Load(), Threats: threats.Load(), Errors: errs.Load(), Current: current.Load().(string)})
				}
			}
		}()
	}

	seen := map[string]bool{}
walk:
	for _, root := range paths {
		root = filepath.Clean(root)
		if seen[strings.ToLower(root)] {
			continue
		}
		seen[strings.ToLower(root)] = true
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				errs.Add(1)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if excluded(p) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != root && skipDirNames[strings.ToLower(d.Name())] {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			select {
			case jobs <- p:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		if ctx.Err() != nil || err == context.Canceled {
			res.Canceled = true
			break walk
		}
	}
	close(jobs)
	wg.Wait()
	close(done)
	res.Files = files.Load()
	res.Errors = errs.Load()
	res.Duration = time.Since(start)
	if ctx.Err() != nil {
		res.Canceled = true
	}
	return &res
}
