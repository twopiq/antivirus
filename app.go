package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/quarantine"
	"github.com/twopiq/antivirus/internal/sigdb"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

type app struct {
	dataDir string
	store   sigdb.Store
	cur     atomic.Pointer[engine.Engine]
	q       *quarantine.Store
	// action: ask — so'rash, report — faqat hisobot, auto — XAVFLI fayllarni
	// karantinga, shubhalilar haqida xabar, quarantine — hammasini karantinga, delete — o'chirish.
	action   string
	workers  int
	maxSize  int64
	quiet    bool
	useCache bool
	exclude  []string
	cache    *scanCache
	state    *appState
}

func newApp(action string, workers int, maxSizeMB int64) (*app, error) {
	dir := system.DataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ma'lumotlar papkasini yaratib bo'lmadi: %w", err)
	}
	a := &app{dataDir: dir, store: sigdb.Store{Root: dir}, action: action, workers: workers, maxSize: maxSizeMB << 20, useCache: true}
	a.store.MigrateLegacy()
	if err := a.reloadEngine(); err != nil {
		return nil, err
	}
	var err error
	a.q, err = quarantine.Open(filepath.Join(dir, "Quarantine"))
	if err != nil {
		return nil, fmt.Errorf("karantin papkasini ochib bo'lmadi: %w", err)
	}
	a.exclude = []string{dir}
	if exe, err := os.Executable(); err == nil {
		a.exclude = append(a.exclude, exe)
	}
	a.exclude = append(a.exclude, readLines(a.exclusionsPath())...)
	a.state = loadState(filepath.Join(dir, "state.json"))
	a.cache = openCache(filepath.Join(dir, "cache.bin"))
	return a, nil
}

// eng joriy skaner (baza yangilanganda almashtiriladi).
func (a *app) eng() *engine.Engine { return a.cur.Load() }

var trustCache sync.Map

func cachedTrust(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	key := fmt.Sprintf("%s|%d|%d", strings.ToLower(path), st.Size(), st.ModTime().UnixNano())
	if v, ok := trustCache.Load(key); ok {
		return v.(bool)
	}
	ok := system.VerifySignature(path)
	trustCache.Store(key, ok)
	return ok
}

// reloadEngine virus bazasini qayta ochadi va yangi skaner yaratadi.
func (a *app) reloadEngine() error {
	db, err := a.store.Open()
	if err != nil {
		return fmt.Errorf("virus bazasini ochib bo'lmadi: %w", err)
	}
	e := engine.New(db)
	if a.maxSize > 0 {
		e.MaxSize = a.maxSize
	}
	e.Trusted = cachedTrust
	for _, l := range readLines(filepath.Join(a.store.SourcesDir(), "allow.txt")) {
		if h, _, ok := sigdb.ParseListLine(l); ok && len(h) == 32 {
			e.Allow[hex.EncodeToString(h)] = true
		}
	}
	a.cur.Store(e)
	return nil
}

func (a *app) dbVersion() string {
	if db := a.eng().DB; db != nil {
		return db.Version
	}
	return "ichki"
}

// excluded yo'l istisno qilinganmi (ma'lumotlar papkasi, dasturning o'zi, foydalanuvchi istisnolari).
func (a *app) excluded(p string) bool {
	lp := strings.ToLower(filepath.Clean(p))
	for _, x := range a.exclude {
		lx := strings.ToLower(filepath.Clean(x))
		if lp == lx || strings.HasPrefix(lp, lx+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (a *app) exclusionsPath() string { return filepath.Join(a.dataDir, "exclusions.txt") }

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func (a *app) quarantineCount() int {
	items, _ := a.q.List()
	return len(items)
}

func (a *app) printf(format string, args ...any) {
	if !a.quiet {
		fmt.Printf(format, args...)
	}
}

func (a *app) println(s string) {
	if !a.quiet {
		fmt.Println(s)
	}
}

func (a *app) signatureCount() int {
	return a.eng().DB.Count() + 1
}

func (a *app) printVersion() {
	fmt.Printf("Qalqon Antivirus v%s\n", version)
	fmt.Printf("Virus bazasi: %s ta imzo (versiya %s)\n", sigdb.FormatCount(a.signatureCount()), a.dbVersion())
	if db := a.eng().DB; db != nil {
		fmt.Printf("  xesh: %s, PE bo'lim: %s, tana: %s\n  manbalar: %s\n", db.Info["hashes"], db.Info["sections"], db.Info["body"], db.Info["sources"])
	} else {
		fmt.Println(ui.Yellow("Baza hali yuklanmagan — \"qalqon update\" buyrug'ini bajaring."))
	}
	fmt.Printf("Ma'lumotlar papkasi: %s\n", a.dataDir)
}

// scan berilgan yo'llarni jarayon satri bilan tekshiradi. Ctrl+C tekshiruvni to'xtatadi.
func (a *app) scan(title string, paths []string, useCache bool) *engine.Result {
	a.println(ui.Bold("\n▶ " + title))
	if len(paths) == 0 {
		a.println(ui.Yellow("Tekshiriladigan papka topilmadi."))
		return &engine.Result{}
	}
	if a.eng().DB == nil {
		a.println(ui.Yellow("  Diqqat: virus bazasi yuklanmagan — faqat evristik tekshiruv. \"qalqon update\" ni bajaring."))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a.println(ui.Dim("  (to'xtatish uchun Ctrl+C)"))
	opt := engine.Options{Workers: a.workers, Exclude: a.exclude}
	if !a.quiet {
		opt.OnProgress = func(p engine.Progress) {
			th := fmt.Sprint(p.Threats)
			if p.Threats > 0 {
				th = ui.Red(th)
			}
			ui.Status(fmt.Sprintf("  Tekshirildi: %d  Tahdid: %s  %s", p.Files, th, ui.Shorten(p.Current, 60)))
		}
	}
	if useCache && a.useCache && a.cache != nil {
		ver := a.dbVersion() + "/" + version
		opt.Skip = func(p string, info os.FileInfo) bool { return a.cache.clean(p, info, ver) }
		opt.OnClean = func(p string, info os.FileInfo) { a.cache.markClean(p, info, ver) }
	}
	res := a.eng().ScanPaths(ctx, paths, opt)
	if !a.quiet {
		ui.EndStatus()
	}
	if a.cache != nil {
		_ = a.cache.save()
	}
	if res.Canceled {
		a.println(ui.Yellow("  Tekshiruv foydalanuvchi tomonidan to'xtatildi."))
	}
	fmt.Printf("  Tekshirilgan fayllar: %d   O'qib bo'lmadi: %d   Vaqt: %s\n", res.Files, res.Errors, res.Duration.Round(time.Second))
	a.logLine(fmt.Sprintf("TEKSHIRUV %q: %d fayl, %d tahdid, %s", title, res.Files, len(res.Threats), res.Duration.Round(time.Second)))
	return res
}

// fileThreat — bitta fayl bo'yicha guruhlangan tahdidlar.
type fileThreat struct {
	Path     string
	Severity engine.Severity
	Names    []string
	Details  []string
	Hash     bool // imzo bo'yicha aniq topilgan
	SHA256   string
}

func groupThreats(ts []engine.Threat) []*fileThreat {
	m := map[string]*fileThreat{}
	var out []*fileThreat
	for _, t := range ts {
		key := strings.ToLower(t.Path)
		ft := m[key]
		if ft == nil {
			ft = &fileThreat{Path: t.Path}
			m[key] = ft
			out = append(out, ft)
		}
		if t.Kind == engine.KindHash || t.Kind == engine.KindBody {
			ft.Hash = true
		}
		if t.Severity > ft.Severity {
			ft.Severity = t.Severity
		}
		if t.Inner == "" && t.SHA256 != "" {
			ft.SHA256 = t.SHA256
		}
		name := t.Name
		if t.Inner != "" {
			name += " [" + t.Inner + "]"
		}
		ft.Names = append(ft.Names, name)
		if t.Detail != "" {
			ft.Details = append(ft.Details, t.Detail)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

func sevLabel(s engine.Severity) string {
	if s == engine.Malicious {
		return ui.Red("[XAVFLI]  ")
	}
	return ui.Yellow("[SHUBHALI]")
}

func (a *app) printThreats(groups []*fileThreat) {
	if a.quiet {
		for _, g := range groups {
			fmt.Printf("%s %s: %s\n", g.Severity, g.Path, strings.Join(g.Names, ", "))
		}
		return
	}
	fmt.Printf("\n%s\n", ui.Red(fmt.Sprintf("⚠ %d ta faylda tahdid topildi:", len(groups))))
	for i, g := range groups {
		fmt.Printf(" %3d. %s %s\n        %s\n", i+1, sevLabel(g.Severity), g.Path, ui.Dim(strings.Join(g.Names, ", ")))
		for _, d := range g.Details {
			fmt.Printf("        %s\n", ui.Dim("→ "+d))
		}
	}
}

// handleThreats topilgan tahdidlarni ko'rsatadi va tanlangan amalni bajaradi.
// Zararsizlantirilgan fayllar sonini va qolganlarini qaytaradi.
func (a *app) handleThreats(ts []engine.Threat) (cleaned int, remaining []*fileThreat) {
	groups := groupThreats(ts)
	a.logThreats(groups)
	if len(groups) == 0 {
		a.println(ui.Green("\n✔ Tahdid topilmadi."))
		return 0, nil
	}
	a.printThreats(groups)

	var selected []*fileThreat
	deleting := a.action == "delete"
	switch a.action {
	case "report":
		return 0, groups
	case "quarantine", "delete":
		selected = groups
	case "auto":
		for _, g := range groups {
			if g.Severity == engine.Malicious {
				selected = append(selected, g)
			}
		}
	default:
		fmt.Println("\nNima qilamiz?")
		fmt.Println("  1. Hammasini karantinga o'tkazish (tavsiya etiladi)")
		fmt.Println("  2. Faqat XAVFLI fayllarni karantinga o'tkazish")
		fmt.Println("  3. Har biri uchun alohida so'rash")
		fmt.Println("  4. Hammasini butunlay o'chirish")
		fmt.Println("  5. Bu fayllar xavfsiz — ishonchli ro'yxatga qo'shish (noto'g'ri aniqlangan)")
		fmt.Println("  0. Hech narsa qilmaslik")
		switch ui.Ask("Tanlang [1]: ") {
		case "", "1":
			selected = groups
		case "2":
			for _, g := range groups {
				if g.Severity == engine.Malicious {
					selected = append(selected, g)
				}
			}
		case "3":
			for _, g := range groups {
				switch strings.ToLower(ui.Ask(fmt.Sprintf("  %s\n    [k]arantin / [o']chirish / [i]shonchli / [Enter] — o'tkazib yuborish: ", g.Path))) {
				case "k":
					selected = append(selected, g)
				case "o", "o'":
					if quarantine.ForceRemove(g.Path) == nil {
						fmt.Println(ui.Green("    ✔ o'chirildi"))
						cleaned++
						continue
					}
				case "i":
					a.allowFile(g)
					continue
				}
				remaining = append(remaining, g)
			}
			for _, g := range selected {
				if a.neutralize(g, false) {
					cleaned++
				} else {
					remaining = append(remaining, g)
				}
			}
			return cleaned, remaining
		case "4":
			if ui.Confirm(ui.Red("Fayllar qaytarib bo'lmaydigan tarzda o'chiriladi. Ishonchingiz komilmi?"), false) {
				deleting = true
				selected = groups
			}
		case "5":
			for _, g := range groups {
				a.allowFile(g)
			}
			return 0, nil
		default:
			return 0, groups
		}
	}

	chosen := map[*fileThreat]bool{}
	for _, g := range selected {
		chosen[g] = true
		if a.neutralize(g, deleting) {
			cleaned++
		} else {
			remaining = append(remaining, g)
		}
	}
	for _, g := range groups {
		if !chosen[g] {
			remaining = append(remaining, g)
		}
	}
	if cleaned > 0 {
		a.println(ui.Green(fmt.Sprintf("✔ %d ta fayl zararsizlantirildi.", cleaned)))
	}
	if len(remaining) > 0 && a.action == "auto" {
		a.println(ui.Yellow(fmt.Sprintf("! %d ta shubhali fayl qoldirildi — ularni ko'rib chiqing.", len(remaining))))
	}
	return cleaned, remaining
}

// allowFile faylni ishonchli ro'yxatga qo'shadi (keyingi tekshiruvlarda e'tiborga olinmaydi).
func (a *app) allowFile(g *fileThreat) {
	sum := g.SHA256
	if sum == "" {
		var err error
		if sum, err = fileSHA256(g.Path); err != nil {
			fmt.Printf("  %s %s: %v\n", ui.Red("✘"), g.Path, err)
			return
		}
	}
	if _, err := a.store.AppendList("allow.txt", []string{sum + " " + g.Path}); err != nil {
		fmt.Printf("  %s %v\n", ui.Red("✘"), err)
		return
	}
	a.eng().Allow[sum] = true
	fmt.Printf("  %s ishonchli ro'yxatga qo'shildi: %s\n", ui.Green("✔"), g.Path)
	a.logLine("ISHONCHLI " + sum + " " + g.Path)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// neutralize faylni ishlatayotgan jarayonlarni to'xtatadi va faylni karantinga o'tkazadi (yoki o'chiradi).
func (a *app) neutralize(g *fileThreat, del bool) bool {
	if a.excluded(g.Path) {
		return false
	}
	if inWindowsDir(g.Path) && !g.Hash {
		a.printf("  %s %s: Windows tizim fayli — xavfsizlik uchun faqat imzo bo'yicha aniqlanganda o'chiriladi\n", ui.Yellow("!"), g.Path)
		return false
	}
	a.killProcessesUsing(g.Path)
	if del {
		if err := quarantine.ForceRemove(g.Path); err != nil {
			a.printf("  %s %s: %v\n", ui.Red("✘"), g.Path, err)
			return false
		}
		a.printf("  %s o'chirildi: %s\n", ui.Green("✔"), g.Path)
		a.logLine("O'CHIRILDI " + g.Path)
		return true
	}
	it, err := a.q.Add(g.Path, strings.Join(g.Names, ", "))
	if err != nil {
		a.printf("  %s %s: %v\n", ui.Red("✘"), g.Path, err)
		return false
	}
	a.printf("  %s karantinga o'tkazildi: %s\n", ui.Green("✔"), g.Path)
	a.logLine("KARANTIN " + it.ID + " " + g.Path)
	return true
}

func (a *app) killProcessesUsing(path string) {
	procs, err := system.Processes()
	if err != nil {
		return
	}
	self := uint32(os.Getpid())
	for _, p := range procs {
		if p.PID != self && p.Path != "" && strings.EqualFold(filepath.Clean(p.Path), filepath.Clean(path)) {
			if err := system.KillProcess(p.PID); err == nil {
				a.printf("  %s jarayon to'xtatildi: %s (PID %d)\n", ui.Green("✔"), p.Name, p.PID)
				a.logLine(fmt.Sprintf("JARAYON TO'XTATILDI %d %s", p.PID, p.Path))
			} else {
				a.printf("  %s jarayonni to'xtatib bo'lmadi: %s (PID %d): %v\n", ui.Red("✘"), p.Name, p.PID, err)
			}
		}
	}
}

var logMu sync.Mutex

func (a *app) logLine(s string) {
	logMu.Lock()
	defer logMu.Unlock()
	dir := filepath.Join(a.dataDir, "logs")
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("15:04:05"), s)
}

func (a *app) logThreats(gs []*fileThreat) {
	for _, g := range gs {
		a.logLine(fmt.Sprintf("TOPILDI %s %s [%s]", g.Severity, g.Path, strings.Join(g.Names, ", ")))
	}
}

func exitCode(remaining []*fileThreat) int {
	if len(remaining) > 0 {
		return 1
	}
	return 0
}

// inWindowsDir yo'l Windows tizim papkasida (C:\Windows) joylashganmi.
func inWindowsDir(p string) bool {
	sr := os.Getenv("SystemRoot")
	if sr == "" {
		return false
	}
	lp, ls := strings.ToLower(filepath.Clean(p)), strings.ToLower(filepath.Clean(sr))
	return strings.HasPrefix(lp, ls+string(filepath.Separator)) && !strings.Contains(lp, `\temp\`)
}

func (a *app) customScan(paths []string) int {
	for i, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			paths[i] = abs
		}
	}
	res := a.scan("Tanlangan yo'llarni tekshirish", paths, true)
	_, rem := a.handleThreats(res.Threats)
	return exitCode(rem)
}

func (a *app) fullScan() int {
	fixed, removable := system.Drives()
	all := append(fixed, removable...)
	code := a.quickScan()
	res := a.scan("To'liq tekshiruv: "+strings.Join(all, " "), all, true)
	_, rem := a.handleThreats(res.Threats)
	a.state.set(func(s *appState) { s.LastFull = time.Now() })
	if code != 0 {
		return code
	}
	return exitCode(rem)
}

// processTargets ishlab turgan jarayonlar va ularga yuklangan (Windows papkasidan tashqaridagi) DLL'lar.
func processTargets() (paths []string, nproc int) {
	procs, _ := system.Processes()
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[strings.ToLower(p)] {
			seen[strings.ToLower(p)] = true
			paths = append(paths, p)
		}
	}
	for _, p := range procs {
		add(p.Path)
		if p.Path == "" {
			continue
		}
		for _, m := range system.ProcessModules(p.PID) {
			if !inWindowsDir(m) {
				add(m)
			}
		}
	}
	return paths, len(procs)
}

func (a *app) quickScan() int {
	paths, nproc := processTargets()
	seen := map[string]bool{}
	for _, p := range paths {
		seen[strings.ToLower(p)] = true
	}
	autoruns := system.Autoruns()
	for _, ar := range autoruns {
		for _, p := range ar.Paths {
			if p != "" && !seen[strings.ToLower(p)] {
				seen[strings.ToLower(p)] = true
				paths = append(paths, p)
			}
		}
	}
	dirs := system.QuickScanDirs()
	a.printf("%s %d ta jarayon, %d ta avtoyuklash yozuvi, %d ta papka\n", ui.Dim("Tekshiriladi:"), nproc, len(autoruns), len(dirs))
	paths = append(paths, dirs...)
	res := a.scan("Tezkor tekshiruv", paths, false)
	_, rem := a.handleThreats(res.Threats)
	n := a.reviewAutoruns(autoruns, true)
	n += a.checkHosts(true)
	a.state.set(func(s *appState) { s.LastQuick = time.Now() })
	if n > 0 && len(rem) == 0 {
		return 1
	}
	return exitCode(rem)
}

func (a *app) processScan() int {
	paths, nproc := processTargets()
	res := a.scan(fmt.Sprintf("Ishlab turgan jarayonlar (%d ta jarayon, %d ta fayl)", nproc, len(paths)), paths, false)
	_, rem := a.handleThreats(res.Threats)
	return exitCode(rem)
}
