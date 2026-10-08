package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

type fileStamp struct {
	size int64
	mod  time.Time
}

// snapshot papkadagi fayllarni (maxDepth chuqurlikkacha) o'qiydi.
func snapshot(root string, maxDepth int) map[string]fileStamp {
	out := map[string]fileStamp{}
	base := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, string(filepath.Separator))-base >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			out[p] = fileStamp{info.Size(), info.ModTime()}
		}
		return nil
	})
	return out
}

// monitor yangi va o'zgargan fayllarni hamda yangi ulangan fleshkalarni kuzatadi.
// Aniq zararli fayllar avtomatik karantinga o'tkaziladi.
func (a *app) monitor() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dirs := system.MonitorDirs()
	fmt.Println(ui.Bold("\n▶ Real vaqt kuzatuvi yoqildi"))
	fmt.Println(ui.Dim("  Kuzatilmoqda: " + strings.Join(dirs, "; ")))
	fmt.Println(ui.Dim("  Yangi ulangan fleshkalar avtomatik tekshiriladi. To'xtatish: Ctrl+C"))

	snaps := map[string]map[string]fileStamp{}
	for _, d := range dirs {
		snaps[d] = snapshot(d, 3)
	}
	_, prevUSB := system.Drives()
	known := map[string]bool{}
	for _, d := range prevUSB {
		known[d] = true
	}
	pending := map[string]fileStamp{} // yozilishi tugashini kutayotgan fayllar

	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println(ui.Yellow("\nKuzatuv to'xtatildi."))
			return 0
		case <-tk.C:
		}
		// 1) Yangi fleshkalar.
		_, usb := system.Drives()
		cur := map[string]bool{}
		for _, d := range usb {
			cur[d] = true
			if !known[d] {
				fmt.Printf("\n%s Yangi fleshka ulandi: %s\n", ui.Cyan(time.Now().Format("15:04:05")), d)
				a.autoClean(usbRootThreats(d), []string{d})
				a.restoreHidden(d)
			}
		}
		known = cur

		// 2) Papkalardagi yangi/o'zgargan fayllar.
		for _, d := range dirs {
			now := snapshot(d, 3)
			old := snaps[d]
			for p, st := range now {
				if o, ok := old[p]; !ok || o != st {
					pending[p] = st
				}
			}
			snaps[d] = now
		}
		var ready []string
		for p, st := range pending {
			info, err := os.Stat(p)
			if err != nil {
				delete(pending, p)
				continue
			}
			// Hajmi o'zgarishdan to'xtagan bo'lsa — yozish tugagan.
			if info.Size() == st.size && info.ModTime().Equal(st.mod) {
				ready = append(ready, p)
				delete(pending, p)
			} else {
				pending[p] = fileStamp{info.Size(), info.ModTime()}
			}
		}
		if len(ready) > 0 {
			a.autoClean(nil, ready)
		}
	}
}

// autoClean yo'llarni jim tekshiradi: XAVFLI fayllarni karantinga o'tkazadi,
// SHUBHALI fayllar haqida xabar beradi.
func (a *app) autoClean(extra []engine.Threat, paths []string) {
	res := a.eng.ScanPaths(context.Background(), paths, engine.Options{Workers: a.workers, Exclude: a.exclude})
	groups := groupThreats(append(extra, res.Threats...))
	a.logThreats(groups)
	ts := ui.Cyan(time.Now().Format("15:04:05"))
	if len(groups) == 0 {
		if len(paths) == 1 {
			fmt.Printf("%s %s %s\n", ts, ui.Green("toza:"), paths[0])
		} else {
			fmt.Printf("%s %s %d ta fayl\n", ts, ui.Green("toza:"), res.Files)
		}
		return
	}
	saved := a.action
	if a.action == "ask" {
		a.action = "quarantine"
	}
	defer func() { a.action = saved }()
	for _, g := range groups {
		fmt.Printf("%s %s %s\n         %s\n", ts, sevLabel(g.Severity), g.Path, ui.Dim(strings.Join(g.Names, ", ")))
		if g.Severity == engine.Malicious && a.action != "report" {
			a.neutralize(g)
		}
	}
	notifyUser(fmt.Sprintf("Qalqon: %d ta tahdid topildi", len(groups)))
}

// notifyUser konsolda ovozli signal beradi.
func notifyUser(string) { fmt.Print("\a") }
