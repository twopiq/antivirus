package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

// skipRootNames — fleshka ildizidagi tizim papkalari (tiklanmaydi).
var skipRootNames = map[string]bool{"system volume information": true, "$recycle.bin": true, "recycler": true}

// usbRootThreats fleshka ildizida "yorliq virusi" belgilarini qidiradi: autorun.inf,
// yashirilgan papkalar nomi bilan yaratilgan .lnk yorliqlar.
func usbRootThreats(root string) []engine.Threat {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	hidden := map[string]bool{}
	for _, e := range ents {
		if system.IsHiddenSystem(filepath.Join(root, e.Name())) {
			hidden[strings.ToLower(e.Name())] = true
		}
	}
	var out []engine.Threat
	for _, e := range ents {
		name := e.Name()
		p := filepath.Join(root, name)
		lower := strings.ToLower(name)
		switch {
		case lower == "autorun.inf" && !e.IsDir():
			data, _ := os.ReadFile(p)
			s := strings.ToLower(string(data))
			t := engine.Threat{Path: p, Name: "Autorun.Inf", Severity: engine.Suspicious, Kind: engine.KindHeuristic}
			if strings.Contains(s, "open=") || strings.Contains(s, "shellexecute=") || strings.Contains(s, `shell\`) {
				t.Name, t.Severity = "Worm.Autorun.Inf", engine.Malicious
			}
			out = append(out, t)
		case strings.HasSuffix(lower, ".lnk") && !e.IsDir():
			stem := strings.TrimSuffix(lower, ".lnk")
			if hidden[stem] || hidden[strings.TrimSpace(stem)] {
				out = append(out, engine.Threat{Path: p, Name: "Worm.LNK.ShortcutVirus", Severity: engine.Malicious, Kind: engine.KindHeuristic})
			}
		}
	}
	return out
}

func (a *app) usbScan(args []string) int {
	drives := args
	if len(drives) == 0 {
		_, drives = system.Drives()
	}
	if len(drives) == 0 {
		fmt.Println(ui.Yellow("Fleshka (olinadigan disk) topilmadi."))
		if a.action == "ask" {
			p := strings.Trim(ui.Ask("Disk harfi yoki yo'lni kiriting (masalan E:\\), Enter — bekor qilish: "), `"' `)
			if p == "" {
				return 0
			}
			if len(p) == 2 && p[1] == ':' {
				p += `\`
			}
			drives = []string{p}
		} else {
			return 0
		}
	}
	code := 0
	for _, root := range drives {
		if len(root) == 2 && root[1] == ':' {
			root += `\`
		}
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			fmt.Println(ui.Red("Disk topilmadi: " + root))
			code = 1
			continue
		}
		extra := usbRootThreats(root)
		res := a.scan("Fleshkani tekshirish: "+root, []string{root})
		_, rem := a.handleThreats(append(extra, res.Threats...))
		if len(rem) > 0 {
			code = 1
		}
		a.restoreHidden(root)
	}
	return code
}

// restoreHidden virus yashirgan fayl va papkalarni yana ko'rinadigan qiladi.
func (a *app) restoreHidden(root string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var hidden []string
	for _, e := range ents {
		if skipRootNames[strings.ToLower(e.Name())] {
			continue
		}
		p := filepath.Join(root, e.Name())
		if system.IsHiddenSystem(p) {
			hidden = append(hidden, p)
		}
	}
	if len(hidden) == 0 {
		return
	}
	fmt.Printf("\n%s\n", ui.Bold(fmt.Sprintf("Fleshkada %d ta yashirilgan fayl/papka bor (virus ularni yashirgan bo'lishi mumkin):", len(hidden))))
	for _, h := range hidden {
		fmt.Println("   " + h)
	}
	switch a.action {
	case "report":
		return
	case "ask":
		if !ui.Confirm("Ularni yana ko'rinadigan qilaylikmi?", true) {
			return
		}
	}
	n := 0
	for _, h := range hidden {
		if err := system.Unhide(h); err != nil {
			fmt.Printf("  %s %s: %v\n", ui.Red("✘"), h, err)
			continue
		}
		n++
		// Ba'zi viruslar fayllarni nomsiz (bo'shliq yoki NBSP) papkaga ko'chiradi.
		if strings.TrimSpace(strings.ReplaceAll(filepath.Base(h), "\u00a0", " ")) == "" {
			a.renameBlankDir(h)
		}
	}
	fmt.Println(ui.Green(fmt.Sprintf("✔ %d ta fayl/papka tiklandi.", n)))
	a.logLine(fmt.Sprintf("TIKLANDI %d ta yashirin element: %s", n, root))
}

// renameBlankDir nomsiz papkani "Tiklangan fayllar" deb qayta nomlaydi.
func (a *app) renameBlankDir(p string) {
	dst := filepath.Join(filepath.Dir(p), "Tiklangan fayllar")
	for i := 2; ; i++ {
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(filepath.Dir(p), fmt.Sprintf("Tiklangan fayllar (%d)", i))
	}
	if err := os.Rename(p, dst); err == nil {
		fmt.Println(ui.Green("  ✔ Nomsiz papka qayta nomlandi: " + dst))
	}
}
