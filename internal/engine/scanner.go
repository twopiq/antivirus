// Package engine — Qalqon antivirusining skanerlash dvigateli: xesh imzolari,
// mazmun qoidalari, evristikalar va ZIP arxivlar ichini tekshirish.
package engine

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
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

	"github.com/twopiq/antivirus/internal/bodysig"
	"github.com/twopiq/antivirus/internal/sigdb"
)

// Kind — tahdid qanday aniqlangani.
type Kind string

const (
	KindHash      Kind = "imzo"
	KindBody      Kind = "tana imzosi"
	KindRule      Kind = "qoida"
	KindHeuristic Kind = "evristika"
)

// Threat — topilgan tahdid.
type Threat struct {
	Path     string   // diskdagi fayl
	Inner    string   // arxiv ichidagi fayl (bo'lsa), masalan "a.zip > b.exe"
	Name     string   // tahdid nomi
	Severity Severity // daraja
	Kind     Kind     // aniqlash usuli
	SHA256   string
	Detail   string // qo'shimcha izoh (masalan evristika sabablari)
}

// Display tahdid joylashuvini foydalanuvchiga ko'rsatish uchun qaytaradi.
func (t Threat) Display() string {
	if t.Inner != "" {
		return t.Path + " > " + t.Inner
	}
	return t.Path
}

// builtinSHA256 — baza yuklanmagan bo'lsa ham ishlaydigan ichki imzolar.
var builtinSHA256 = map[string]string{
	"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}

// Engine — skaner.
type Engine struct {
	DB *sigdb.DB // nil bo'lishi mumkin
	// Allow — foydalanuvchi ishonchli deb belgilagan fayllar (SHA-256, hex).
	Allow map[string]bool
	// Trusted fayl ishonchli raqamli imzoga egami (Windows Authenticode).
	// Faqat evristik "shubhali" natijalarni tasdiqlash uchun chaqiriladi.
	Trusted func(path string) bool
	// MaxSize — mazmuni tekshiriladigan eng katta fayl hajmi (bayt).
	MaxSize int64
	// MaxArchiveEntries — bitta arxivda tekshiriladigan fayllar soni chegarasi.
	MaxArchiveEntries int
	// MaxArchiveDepth — ichma-ich arxivlar chuqurligi.
	MaxArchiveDepth int
	// MaxArchiveBytes — bitta fayldagi arxivlardan ochiladigan jami hajm.
	MaxArchiveBytes int64
}

// New yangi skaner yaratadi.
func New(db *sigdb.DB) *Engine {
	return &Engine{DB: db, Allow: map[string]bool{}, MaxSize: 50 << 20, MaxArchiveEntries: 5000, MaxArchiveDepth: 4, MaxArchiveBytes: 512 << 20}
}

// ScanBytes xotiradagi ma'lumotni (name nomli fayl sifatida) tekshiradi.
func (e *Engine) ScanBytes(name string, data []byte) []Threat {
	return e.scanData(name, data, &scanCtx{path: name, budget: e.MaxArchiveBytes})
}

func (e *Engine) hashes(data []byte) sigdb.Hashes {
	m := md5.Sum(data)
	s := sha256.Sum256(data)
	h := sigdb.Hashes{MD5: m[:], SHA256: s[:]}
	if e.DB.NeedSHA1() {
		x := sha1.Sum(data)
		h.SHA1 = x[:]
	}
	return h
}

// fileType fayl turini mazmuniga qarab aniqlaydi (ClamAV maqsad turlari).
func fileType(data []byte) int {
	switch {
	case isPE(data):
		return bodysig.TargetPE
	case bytes.HasPrefix(data, ole2Magic):
		return bodysig.TargetOLE2
	case bytes.HasPrefix(data, []byte("%PDF-")) || bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF-")):
		return bodysig.TargetPDF
	case bytes.HasPrefix(data, []byte{0xCA, 0xFE, 0xBA, 0xBE}):
		return bodysig.TargetJava
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}), bytes.HasPrefix(data, []byte("\x89PNG")), bytes.HasPrefix(data, []byte("GIF8")):
		return bodysig.TargetGraphics
	}
	return bodysig.TargetAny
}

func (e *Engine) scanData(name string, data []byte, sc *scanCtx) []Threat {
	h := e.hashes(data)
	hexsum := hex.EncodeToString(h.SHA256)
	if e.Allow[hexsum] || e.DB.Allowed(h, int64(len(data))) {
		return nil
	}
	var out []Threat
	if n, ok := builtinSHA256[hexsum]; ok {
		out = append(out, Threat{Name: n, Severity: Malicious, Kind: KindHash})
	} else if n, ok := e.DB.LookupFile(h, int64(len(data))); ok {
		out = append(out, Threat{Name: n, Severity: Malicious, Kind: KindHash})
	}

	ft := fileType(data)
	info := bodysig.FileInfo{Type: ft, EP: -1}
	if ft == bodysig.TargetPE {
		pi := analyzePE(data)
		info.EP = pi.ep
		if n, ok := sectionMatch(e.DB, pi); ok {
			out = append(out, Threat{Name: n, Severity: Malicious, Kind: KindHash})
		}
		if pi.score >= peThreshold {
			out = append(out, Threat{Name: "Heur.PE.Suspicious", Severity: Suspicious, Kind: KindHeuristic, Detail: strings.Join(pi.reasons, "; ")})
		}
	}
	if e.DB != nil {
		for _, n := range e.DB.Body.Scan(data, info) {
			out = append(out, Threat{Name: n, Severity: Malicious, Kind: KindBody})
		}
	}
	switch {
	case ft == bodysig.TargetOLE2:
		out = append(out, checkOLE2(data)...)
	case ft == bodysig.TargetPDF:
		out = append(out, checkPDF(data)...)
	case bytes.HasPrefix(data, []byte("{\\rt")):
		out = append(out, checkRTF(data)...)
	}
	out = append(out, matchRules(name, data)...)
	out = append(out, checkContent(name, data)...)
	out = append(out, checkName(name)...)

	if sc.depth < e.MaxArchiveDepth {
		switch {
		case isZipData(data):
			out = append(out, e.scanZip(data, sc)...)
		case isGzip(data):
			out = append(out, e.scanGzip(name, data, sc)...)
		case isTar(data):
			out = append(out, e.scanTar(data, sc)...)
		}
	}
	for i := range out {
		if out[i].SHA256 == "" {
			out[i].SHA256 = hexsum
		}
	}
	return dedupe(out)
}

// signableExts — Authenticode imzosi bo'lishi mumkin bo'lgan fayllar.
var signableExts = map[string]bool{".exe": true, ".dll": true, ".sys": true, ".scr": true, ".msi": true, ".ocx": true, ".cpl": true, ".ps1": true, ".cab": true}

// dropTrusted ishonchli imzolangan fayllardagi shubhali evristik natijalarni olib tashlaydi.
func (e *Engine) dropTrusted(path string, ts []Threat) []Threat {
	if e.Trusted == nil || !signableExts[strings.ToLower(filepath.Ext(path))] {
		return ts
	}
	weak := false
	for _, t := range ts {
		if t.Inner == "" && t.Severity == Suspicious && (t.Kind == KindHeuristic || t.Kind == KindRule) {
			weak = true
		}
	}
	if !weak || !e.Trusted(path) {
		return ts
	}
	out := ts[:0]
	for _, t := range ts {
		if t.Inner == "" && t.Severity == Suspicious && (t.Kind == KindHeuristic || t.Kind == KindRule) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// bigExecutable — MaxSize dan katta bo'lsa ham xeshi tekshiriladigan fayllar.
var bigExecutable = map[string]bool{".exe": true, ".dll": true, ".msi": true, ".scr": true, ".sys": true}

// ScanFile bitta faylni tekshiradi. Bir faylda bir nechta tahdid bo'lishi mumkin.
func (e *Engine) ScanFile(path string) ([]Threat, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil
	}
	var threats []Threat
	if st.Size() > e.MaxSize {
		threats = checkName(path)
		if bigExecutable[strings.ToLower(filepath.Ext(path))] && st.Size() <= 512<<20 {
			if t, ok, err := e.hashLargeFile(path); err == nil && ok {
				threats = append(threats, t)
			}
		}
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		threats = e.scanData(path, data, &scanCtx{path: path, budget: e.MaxArchiveBytes})
	}
	threats = e.dropTrusted(path, threats)
	for i := range threats {
		threats[i].Path = path
	}
	return threats, nil
}

// hashLargeFile katta faylni o'qib, faqat xesh imzolari bo'yicha tekshiradi.
func (e *Engine) hashLargeFile(path string) (Threat, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return Threat{}, false, err
	}
	defer f.Close()
	m, s := md5.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(m, s), f)
	if err != nil {
		return Threat{}, false, err
	}
	h := sigdb.Hashes{MD5: m.Sum(nil), SHA256: s.Sum(nil)}
	if e.Allow[hex.EncodeToString(h.SHA256)] || e.DB.Allowed(h, n) {
		return Threat{}, false, nil
	}
	if name, ok := e.DB.LookupFile(h, n); ok {
		return Threat{Name: name, Severity: Malicious, Kind: KindHash, SHA256: hex.EncodeToString(h.SHA256)}, true, nil
	}
	return Threat{}, false, nil
}

func dedupe(ts []Threat) []Threat {
	seen := map[string]bool{}
	out := ts[:0]
	for _, t := range ts {
		k := t.Inner + "\x00" + t.Name
		if seen[k] {
			continue
		}
		seen[k] = true
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
	// Skip true qaytarsa fayl tekshirilmaydi (masalan, kesh bo'yicha toza).
	Skip func(path string, info fs.FileInfo) bool
	// OnClean fayl toza deb topilganda chaqiriladi (keshga yozish uchun).
	OnClean func(path string, info fs.FileInfo)
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
				var info fs.FileInfo
				if opt.Skip != nil || opt.OnClean != nil {
					info, _ = os.Stat(p)
				}
				if opt.Skip != nil && info != nil && opt.Skip(p, info) {
					files.Add(1)
					continue
				}
				ts, err := e.ScanFile(p)
				files.Add(1)
				if err != nil {
					errs.Add(1)
					continue
				}
				if len(ts) == 0 {
					if opt.OnClean != nil && info != nil {
						opt.OnClean(p, info)
					}
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
		// Ildiz yo'l ramziy havola bo'lsa — uning manziliga o'tamiz (ichkaridagi havolalarga emas).
		if st, err := os.Lstat(root); err == nil && st.Mode()&os.ModeSymlink != 0 {
			if r, err := filepath.EvalSymlinks(root); err == nil {
				root = r
			}
		}
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
