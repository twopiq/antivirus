package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/quarantine"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

type app struct {
	dataDir string
	sigPath string
	eng     *engine.Engine
	q       *quarantine.Store
	action  string
	workers int
	exclude []string
}

func newApp(action string, workers int, maxSizeMB int64) (*app, error) {
	dir := system.DataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ma'lumotlar papkasini yaratib bo'lmadi: %w", err)
	}
	a := &app{dataDir: dir, sigPath: filepath.Join(dir, "signatures.txt"), action: action, workers: workers}
	db, err := engine.LoadSignatureDB(a.sigPath)
	if err != nil {
		return nil, fmt.Errorf("virus bazasini o'qib bo'lmadi: %w", err)
	}
	a.eng = engine.New(db)
	if maxSizeMB > 0 {
		a.eng.MaxSize = maxSizeMB << 20
	}
	a.q, err = quarantine.Open(filepath.Join(dir, "Quarantine"))
	if err != nil {
		return nil, fmt.Errorf("karantin papkasini ochib bo'lmadi: %w", err)
	}
	a.exclude = []string{dir}
	if exe, err := os.Executable(); err == nil {
		a.exclude = append(a.exclude, exe)
	}
	a.exclude = append(a.exclude, readLines(filepath.Join(dir, "exclusions.txt"))...)
	return a, nil
}

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

func (a *app) printVersion() {
	fmt.Printf("Qalqon Antivirus v%s\n", version)
	fmt.Printf("Virus bazasi: %d ta imzo (%s)\n", a.eng.DB.Len(), a.sigPath)
	if st, err := os.Stat(a.sigPath); err == nil {
		fmt.Printf("Baza yangilangan: %s\n", st.ModTime().Format("2006-01-02 15:04"))
	} else {
		fmt.Println(ui.Yellow("Baza hali yuklanmagan — \"qalqon update\" buyrug'ini bajaring."))
	}
	fmt.Printf("Ma'lumotlar papkasi: %s\n", a.dataDir)
}

// scan berilgan yo'llarni jarayon satri bilan tekshiradi. Ctrl+C tekshiruvni to'xtatadi.
func (a *app) scan(title string, paths []string) *engine.Result {
	fmt.Println(ui.Bold("\n▶ " + title))
	if len(paths) == 0 {
		fmt.Println(ui.Yellow("Tekshiriladigan papka topilmadi."))
		return &engine.Result{}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Println(ui.Dim("  (to'xtatish uchun Ctrl+C)"))
	res := a.eng.ScanPaths(ctx, paths, engine.Options{
		Workers: a.workers,
		Exclude: a.exclude,
		OnProgress: func(p engine.Progress) {
			th := fmt.Sprint(p.Threats)
			if p.Threats > 0 {
				th = ui.Red(th)
			}
			ui.Status(fmt.Sprintf("  Tekshirildi: %d  Tahdid: %s  %s", p.Files, th, ui.Shorten(p.Current, 60)))
		},
	})
	ui.EndStatus()
	if res.Canceled {
		fmt.Println(ui.Yellow("  Tekshiruv foydalanuvchi tomonidan to'xtatildi."))
	}
	fmt.Printf("  Tekshirilgan fayllar: %d   O'qib bo'lmadi: %d   Vaqt: %s\n", res.Files, res.Errors, res.Duration.Round(time.Second))
	return res
}

// fileThreat — bitta fayl bo'yicha guruhlangan tahdidlar.
type fileThreat struct {
	Path     string
	Severity engine.Severity
	Names    []string
	Hash     bool // imzo (xesh) bo'yicha aniq topilgan
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
		if t.Kind == engine.KindHash {
			ft.Hash = true
		}
		if t.Severity > ft.Severity {
			ft.Severity = t.Severity
		}
		name := t.Name
		if t.Inner != "" {
			name += " [" + t.Inner + "]"
		}
		ft.Names = append(ft.Names, name)
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

// handleThreats topilgan tahdidlarni ko'rsatadi va tanlangan amalni bajaradi.
// Zararsizlantirilgan fayllar sonini va qolganlarini qaytaradi.
func (a *app) handleThreats(ts []engine.Threat) (cleaned int, remaining []*fileThreat) {
	groups := groupThreats(ts)
	a.logThreats(groups)
	if len(groups) == 0 {
		fmt.Println(ui.Green("\n✔ Tahdid topilmadi. Kompyuteringiz toza."))
		return 0, nil
	}
	fmt.Printf("\n%s\n", ui.Red(fmt.Sprintf("⚠ %d ta faylda tahdid topildi:", len(groups))))
	for i, g := range groups {
		fmt.Printf(" %3d. %s %s\n        %s\n", i+1, sevLabel(g.Severity), g.Path, ui.Dim(strings.Join(g.Names, ", ")))
	}

	var selected []*fileThreat
	switch a.action {
	case "report":
		return 0, groups
	case "quarantine", "delete":
		selected = groups
	default:
		fmt.Println("\nNima qilamiz?")
		fmt.Println("  1. Hammasini karantinga o'tkazish (tavsiya etiladi)")
		fmt.Println("  2. Faqat XAVFLI fayllarni karantinga o'tkazish")
		fmt.Println("  3. Har biri uchun alohida so'rash")
		fmt.Println("  4. Hammasini butunlay o'chirish")
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
				if ui.Confirm(fmt.Sprintf("  %s ni karantinga o'tkazish?", g.Path), g.Severity == engine.Malicious) {
					selected = append(selected, g)
				}
			}
		case "4":
			if ui.Confirm(ui.Red("Fayllar qaytarib bo'lmaydigan tarzda o'chiriladi. Ishonchingiz komilmi?"), false) {
				a.action = "delete"
				defer func() { a.action = "ask" }()
				selected = groups
			}
		default:
			return 0, groups
		}
	}

	chosen := map[*fileThreat]bool{}
	for _, g := range selected {
		chosen[g] = true
		if a.neutralize(g) {
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
		fmt.Println(ui.Green(fmt.Sprintf("✔ %d ta fayl zararsizlantirildi.", cleaned)))
	}
	return cleaned, remaining
}

// neutralize faylni ishlatayotgan jarayonlarni to'xtatadi va faylni karantinga o'tkazadi (yoki o'chiradi).
func (a *app) neutralize(g *fileThreat) bool {
	if inWindowsDir(g.Path) && !g.Hash {
		fmt.Printf("  %s %s: Windows tizim fayli — xavfsizlik uchun faqat imzo bo'yicha aniqlanganda o'chiriladi\n", ui.Yellow("!"), g.Path)
		return false
	}
	a.killProcessesUsing(g.Path)
	if a.action == "delete" {
		if err := quarantine.ForceRemove(g.Path); err != nil {
			fmt.Printf("  %s %s: %v\n", ui.Red("✘"), g.Path, err)
			return false
		}
		fmt.Printf("  %s o'chirildi: %s\n", ui.Green("✔"), g.Path)
		a.logLine("O'CHIRILDI " + g.Path)
		return true
	}
	it, err := a.q.Add(g.Path, strings.Join(g.Names, ", "))
	if err != nil {
		fmt.Printf("  %s %s: %v\n", ui.Red("✘"), g.Path, err)
		return false
	}
	fmt.Printf("  %s karantinga o'tkazildi: %s\n", ui.Green("✔"), g.Path)
	a.logLine("KARANTIN " + it.ID + " " + g.Path)
	return true
}

func (a *app) killProcessesUsing(path string) {
	procs, err := system.Processes()
	if err != nil {
		return
	}
	for _, p := range procs {
		if p.Path != "" && strings.EqualFold(filepath.Clean(p.Path), filepath.Clean(path)) {
			if err := system.KillProcess(p.PID); err == nil {
				fmt.Printf("  %s jarayon to'xtatildi: %s (PID %d)\n", ui.Green("✔"), p.Name, p.PID)
				a.logLine(fmt.Sprintf("JARAYON TO'XTATILDI %d %s", p.PID, p.Path))
			} else {
				fmt.Printf("  %s jarayonni to'xtatib bo'lmadi: %s (PID %d): %v\n", ui.Red("✘"), p.Name, p.PID, err)
			}
		}
	}
}

func (a *app) logLine(s string) {
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

func (a *app) customScan(paths []string) int {
	for i, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			paths[i] = abs
		}
	}
	res := a.scan("Tanlangan yo'llarni tekshirish", paths)
	_, rem := a.handleThreats(res.Threats)
	return exitCode(rem)
}

func (a *app) fullScan() int {
	fixed, removable := system.Drives()
	res := a.scan("To'liq tekshiruv: "+strings.Join(append(fixed, removable...), " "), append(fixed, removable...))
	_, rem := a.handleThreats(res.Threats)
	return exitCode(rem)
}

func (a *app) quickScan() int {
	var paths []string
	procs, _ := system.Processes()
	seen := map[string]bool{}
	for _, p := range procs {
		if p.Path != "" && !seen[strings.ToLower(p.Path)] {
			seen[strings.ToLower(p.Path)] = true
			paths = append(paths, p.Path)
		}
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
	fmt.Printf("%s %d ta jarayon, %d ta avtoyuklash yozuvi, papkalar: %s\n", ui.Dim("Tekshiriladi:"), len(procs), len(autoruns), ui.Dim(strings.Join(dirs, "; ")))
	paths = append(paths, dirs...)
	res := a.scan("Tezkor tekshiruv", paths)
	_, rem := a.handleThreats(res.Threats)
	if n := a.reviewAutoruns(autoruns, true); n > 0 && len(rem) == 0 {
		return 1
	}
	return exitCode(rem)
}

func (a *app) processScan() int {
	procs, err := system.Processes()
	if err != nil {
		fmt.Println(ui.Red("Jarayonlar ro'yxatini olib bo'lmadi: " + err.Error()))
		return 1
	}
	var paths []string
	seen := map[string]bool{}
	for _, p := range procs {
		if p.Path != "" && !seen[strings.ToLower(p.Path)] {
			seen[strings.ToLower(p.Path)] = true
			paths = append(paths, p.Path)
		}
	}
	res := a.scan(fmt.Sprintf("Ishlab turgan jarayonlar (%d ta dastur)", len(paths)), paths)
	_, rem := a.handleThreats(res.Threats)
	return exitCode(rem)
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
