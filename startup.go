package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

// autorunVerdict — avtoyuklash yozuvini baholash natijasi.
type autorunVerdict struct {
	Entry    system.Autorun
	Severity engine.Severity // 0 — toza
	Reason   string
	Missing  bool // dastur fayli mavjud emas
}

func (a *app) assessAutorun(ar system.Autorun) autorunVerdict {
	v := autorunVerdict{Entry: ar}
	if system.WinlogonModified(ar) {
		v.Severity, v.Reason = engine.Malicious, "Winlogon qiymati o'zgartirilgan (standart: "+ar.Default+")"
	}
	for i, p := range ar.Paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if i == 0 {
				v.Missing = true
			}
			continue
		}
		ts, _ := a.eng.ScanFile(p)
		for _, t := range ts {
			if t.Severity > v.Severity {
				v.Severity, v.Reason = t.Severity, t.Name+" ("+p+")"
			}
		}
	}
	cmd := strings.ToLower(ar.Command)
	if v.Severity == 0 && len(ar.Paths) > 0 && system.IsLauncher(ar.Paths[0]) {
		for _, p := range ar.Paths[1:] {
			if system.InUserWritableDir(p) {
				v.Severity, v.Reason = engine.Suspicious, "skript/DLL Temp yoki AppData papkasidan ishga tushiriladi"
			}
		}
		if strings.Contains(cmd, "-enc") || strings.Contains(cmd, "hidden") || strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://") {
			v.Severity, v.Reason = engine.Suspicious, "yashirin yoki internetdan yuklovchi buyruq"
		}
	}
	return v
}

// reviewAutoruns shubhali avtoyuklash yozuvlarini ko'rsatadi va o'chirishni taklif qiladi.
// onlyBad=true bo'lsa faqat muammoli yozuvlar chiqariladi. Qolgan muammoli yozuvlar sonini qaytaradi.
func (a *app) reviewAutoruns(list []system.Autorun, onlyBad bool) int {
	var bad []autorunVerdict
	all := make([]autorunVerdict, 0, len(list))
	for _, ar := range list {
		v := a.assessAutorun(ar)
		all = append(all, v)
		if v.Severity > 0 {
			bad = append(bad, v)
		}
	}
	if !onlyBad {
		fmt.Println(ui.Bold("\n▶ Avtoyuklash dasturlari"))
		for i, v := range all {
			status := ui.Green("[TOZA]    ")
			switch {
			case v.Severity == engine.Malicious:
				status = ui.Red("[XAVFLI]  ")
			case v.Severity == engine.Suspicious:
				status = ui.Yellow("[SHUBHALI]")
			case v.Missing:
				status = ui.Dim("[FAYL YO'Q]")
			}
			fmt.Printf(" %3d. %s %s\n        %s\n        %s\n", i+1, status, ui.Bold(v.Entry.Name), ui.Dim(v.Entry.Location), ui.Shorten(v.Entry.Command, 100))
			if v.Reason != "" {
				fmt.Printf("        → %s\n", v.Reason)
			}
		}
	}
	if len(bad) == 0 {
		if onlyBad {
			fmt.Println(ui.Green("✔ Avtoyuklashda shubhali yozuv yo'q."))
		}
		return 0
	}
	fmt.Println(ui.Red(fmt.Sprintf("\n⚠ Avtoyuklashda %d ta muammoli yozuv:", len(bad))))
	remaining := 0
	for _, v := range bad {
		fmt.Printf("  %s %s — %s\n        %s\n", sevLabel(v.Severity), ui.Bold(v.Entry.Name), v.Reason, ui.Dim(v.Entry.Location))
		remove := false
		switch a.action {
		case "quarantine", "delete":
			remove = v.Severity == engine.Malicious
		case "ask":
			q := "  Avtoyuklashdan o'chirilsinmi?"
			if v.Entry.Kind == system.AutorunWinlogon {
				q = "  Standart qiymat tiklansinmi?"
			}
			remove = ui.Confirm(q, v.Severity == engine.Malicious)
		}
		if !remove {
			remaining++
			continue
		}
		if err := a.removeAutorun(v.Entry); err != nil {
			fmt.Printf("  %s %v\n", ui.Red("✘"), err)
			remaining++
		} else {
			fmt.Printf("  %s %s olib tashlandi\n", ui.Green("✔"), v.Entry.Name)
		}
	}
	return remaining
}

func (a *app) removeAutorun(ar system.Autorun) error {
	// Zaxira nusxasi: noto'g'ri o'chirilgan yozuvni qo'lda tiklash uchun.
	if f, err := os.OpenFile(filepath.Join(a.dataDir, "autoruns-backup.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%s\t%s\t%s\n", ar.Location, ar.Name, ar.Command)
		f.Close()
	}
	if ar.Kind == system.AutorunFile {
		// Startup papkasidagi fayl — karantinga.
		_, err := a.q.Add(filepath.Join(ar.Location, ar.Name), "Avtoyuklash: "+ar.Name)
		return err
	}
	a.logLine("AVTOYUKLASH O'CHIRILDI " + ar.Location + `\` + ar.Name + " = " + ar.Command)
	return system.RemoveAutorun(ar)
}

func (a *app) startupCheck() int {
	list := system.Autoruns()
	rem := a.reviewAutoruns(list, false)
	if a.action == "ask" && len(list) > 0 {
		for {
			s := ui.Ask("\nBoshqa yozuvni o'chirish uchun raqamini kiriting (Enter — chiqish): ")
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > len(list) {
				break
			}
			ar := list[n-1]
			if ar.Kind == system.AutorunWinlogon {
				fmt.Println(ui.Yellow("Winlogon qiymatlari faqat o'zgartirilgan bo'lsa tiklanadi."))
				continue
			}
			if ui.Confirm(fmt.Sprintf("%q avtoyuklashdan o'chirilsinmi?", ar.Name), false) {
				if err := a.removeAutorun(ar); err != nil {
					fmt.Println(ui.Red("✘ " + err.Error()))
				} else {
					fmt.Println(ui.Green("✔ O'chirildi"))
				}
			}
		}
	}
	if rem > 0 {
		return 1
	}
	return 0
}
