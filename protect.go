package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

// riskyExts — Temp/AppData kabi "shovqinli" papkalarda kuzatiladigan fayl turlari.
var riskyExts = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true, ".pif": true, ".bat": true, ".cmd": true, ".vbs": true,
	".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".ps1": true, ".lnk": true, ".msi": true,
	".jar": true, ".cpl": true, ".sys": true, ".zip": true, ".docm": true, ".xlsm": true, ".doc": true, ".xls": true,
}

// partialExts — yuklanayotgan (hali tugamagan) fayllar.
var partialExts = map[string]bool{".crdownload": true, ".part": true, ".partial": true, ".download": true, ".tmp": true, ".opdownload": true}

// protect real vaqt himoyasi: yangi fayllar, ishga tushgan dasturlar va ulangan fleshkalar
// avtomatik tekshiriladi. XAVFLI fayllar darhol karantinga o'tkaziladi.
func (a *app) protect(background bool) int {
	if !system.SingleInstance("QalqonHimoya") {
		if !background {
			fmt.Println(ui.Yellow("Real vaqt himoyasi allaqachon ishlab turibdi."))
		}
		return 0
	}
	if background {
		system.HideConsole()
		a.quiet = true
	}
	saved := a.action
	a.action = "auto"
	defer func() { a.action = saved }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	userDirs := system.MonitorDirs()
	riskyDirs := system.MonitorRiskyDirs()
	a.println(ui.Bold("\n▶ Real vaqt himoyasi yoqildi"))
	a.println(ui.Dim("  Kuzatilmoqda: " + strings.Join(append(append([]string{}, userDirs...), riskyDirs...), "; ")))
	a.println(ui.Dim("  Yangi dasturlar va ulangan fleshkalar avtomatik tekshiriladi. To'xtatish: Ctrl+C"))
	a.logLine("HIMOYA YOQILDI")

	r := &realtime{a: a, pending: map[string]time.Time{}}
	go system.Watch(ctx, userDirs, func(p string) { r.enqueue(p, false) })
	go system.Watch(ctx, riskyDirs, func(p string) { r.enqueue(p, true) })
	go r.fileWorker(ctx)
	go r.processGuard(ctx)
	go r.usbGuard(ctx)
	go r.dbReloader(ctx)
	<-ctx.Done()
	a.println(ui.Yellow("\nHimoya to'xtatildi."))
	a.logLine("HIMOYA TO'XTATILDI")
	return 0
}

type realtime struct {
	a       *app
	mu      sync.Mutex
	pending map[string]time.Time
	act     sync.Mutex
}

func (r *realtime) enqueue(p string, riskyOnly bool) {
	ext := strings.ToLower(filepath.Ext(p))
	if partialExts[ext] || (riskyOnly && !riskyExts[ext]) {
		return
	}
	if r.a.excluded(p) {
		return
	}
	r.mu.Lock()
	r.pending[p] = time.Now()
	r.mu.Unlock()
}

// fileWorker o'zgarishi to'xtagan (yozilishi tugagan) fayllarni tekshiradi.
func (r *realtime) fileWorker(ctx context.Context) {
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		var ready []string
		r.mu.Lock()
		for p, t := range r.pending {
			if time.Since(t) >= 1500*time.Millisecond {
				ready = append(ready, p)
				delete(r.pending, p)
			}
		}
		r.mu.Unlock()
		for _, p := range ready {
			st, err := os.Stat(p)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			ts, err := r.a.eng().ScanFile(p)
			if err != nil {
				// Fayl hali band bo'lishi mumkin — keyinroq qayta urinamiz.
				if time.Since(st.ModTime()) < time.Minute {
					r.mu.Lock()
					r.pending[p] = time.Now()
					r.mu.Unlock()
				}
				continue
			}
			r.handle("Yangi fayl", ts)
		}
	}
}

// processGuard yangi ishga tushgan jarayonlarni tekshiradi.
func (r *realtime) processGuard(ctx context.Context) {
	seen := map[uint32]string{}
	verdict := map[string]bool{} // yo'l|hajm|vaqt -> toza
	first := true
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		procs, err := system.Processes()
		if err == nil {
			alive := map[uint32]bool{}
			for _, p := range procs {
				alive[p.PID] = true
				if p.Path == "" || seen[p.PID] == p.Path {
					continue
				}
				seen[p.PID] = p.Path
				st, err := os.Stat(p.Path)
				if err != nil {
					continue
				}
				key := fmt.Sprintf("%s|%d|%d", strings.ToLower(p.Path), st.Size(), st.ModTime().UnixNano())
				if verdict[key] {
					continue
				}
				if r.a.excluded(p.Path) || (first && inWindowsDir(p.Path)) {
					verdict[key] = true // tizim jarayonlari tezkor tekshiruvda ko'riladi
					continue
				}
				ts, err := r.a.eng().ScanFile(p.Path)
				if err != nil {
					continue
				}
				if len(ts) == 0 {
					verdict[key] = true
					continue
				}
				r.handle(fmt.Sprintf("Ishga tushgan dastur (PID %d)", p.PID), ts)
			}
			for pid := range seen {
				if !alive[pid] {
					delete(seen, pid)
				}
			}
			if len(verdict) > 20000 {
				verdict = map[string]bool{}
			}
			first = false
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// usbGuard yangi ulangan fleshkalarni tekshiradi va tozalaydi.
func (r *realtime) usbGuard(ctx context.Context) {
	_, prev := system.Drives()
	known := map[string]bool{}
	for _, d := range prev {
		known[d] = true
	}
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		_, usb := system.Drives()
		cur := map[string]bool{}
		for _, d := range usb {
			cur[d] = true
			if known[d] {
				continue
			}
			r.a.printf("\n%s Yangi fleshka ulandi: %s\n", ui.Cyan(time.Now().Format("15:04:05")), d)
			r.a.logLine("FLESHKA ULANDI " + d)
			res := r.a.eng().ScanPaths(ctx, []string{d}, engine.Options{Workers: 2, Exclude: r.a.exclude})
			r.handle("Fleshka "+d, append(usbRootThreats(d), res.Threats...))
			r.act.Lock()
			r.a.restoreHidden(d)
			r.act.Unlock()
		}
		known = cur
	}
}

// dbReloader baza yangilanganda (masalan rejalashtirilgan "update" vazifasidan keyin) uni qayta yuklaydi.
func (r *realtime) dbReloader(ctx context.Context) {
	ver := r.a.store.CurrentVersion()
	tk := time.NewTicker(5 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		if v := r.a.store.CurrentVersion(); v != ver && v != "" {
			// Eski baza yopilmaydi: undan hali boshqa oqimlar foydalanayotgan bo'lishi mumkin.
			if err := r.a.reloadEngine(); err == nil {
				ver = v
				r.a.logLine("BAZA QAYTA YUKLANDI " + v)
			}
		}
	}
}

func (r *realtime) handle(source string, ts []engine.Threat) {
	if len(ts) == 0 {
		return
	}
	r.act.Lock()
	defer r.act.Unlock()
	a := r.a
	groups := groupThreats(ts)
	a.logThreats(groups)
	var msgs []string
	for _, g := range groups {
		a.printf("%s %s %s %s\n         %s\n", ui.Cyan(time.Now().Format("15:04:05")), ui.Dim(source+":"), sevLabel(g.Severity), g.Path, ui.Dim(strings.Join(g.Names, ", ")))
		if g.Severity == engine.Malicious {
			if a.neutralize(g, false) {
				msgs = append(msgs, "Karantinga o'tkazildi: "+g.Path+"\n("+strings.Join(g.Names, ", ")+")")
			} else {
				msgs = append(msgs, "ZARARSIZLANTIRIB BO'LMADI: "+g.Path+"\n("+strings.Join(g.Names, ", ")+")")
			}
		} else {
			msgs = append(msgs, "Shubhali fayl: "+g.Path+"\n("+strings.Join(g.Names, ", ")+")\nTekshirish uchun Qalqon'ni oching.")
		}
	}
	system.Notify("Qalqon Antivirus — tahdid topildi", strings.Join(msgs, "\n\n"))
	fmt.Print("\a")
}
