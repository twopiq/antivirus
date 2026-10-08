package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

var securityTools = map[string]bool{
	"taskmgr.exe": true, "regedit.exe": true, "msconfig.exe": true, "cmd.exe": true, "procexp.exe": true,
	"procexp64.exe": true, "msmpeng.exe": true, "mrt.exe": true, "autoruns.exe": true, "qalqon.exe": true,
	"rstrui.exe": true, "explorer.exe": true, "mmc.exe": true, "perfmon.exe": true, "powershell.exe": true,
}

func (a *app) assessAutorun(ar system.Autorun) autorunVerdict {
	v := autorunVerdict{Entry: ar}
	set := func(s engine.Severity, r string) {
		if s > v.Severity {
			v.Severity, v.Reason = s, r
		}
	}
	if system.WinlogonModified(ar) {
		if ar.Name == "AppInit_DLLs" {
			set(engine.Suspicious, "har bir dasturga DLL yuklanadi (AppInit_DLLs)")
		} else {
			set(engine.Malicious, "Winlogon qiymati o'zgartirilgan (standart: "+ar.Default+")")
		}
	}
	if ar.Kind == system.AutorunIFEO {
		if securityTools[strings.ToLower(ar.Name)] {
			set(engine.Malicious, ar.Name+" boshqa dasturga almashtirilgan (IFEO)")
		} else {
			set(engine.Suspicious, ar.Name+" ishga tushganda boshqa dastur ishlaydi (IFEO)")
		}
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
		ts, _ := a.eng().ScanFile(p)
		for _, t := range ts {
			set(t.Severity, t.Name+" ("+p+")")
		}
	}
	if ar.Disabled {
		return v
	}
	cmd := strings.ToLower(ar.Command)
	if len(ar.Paths) > 0 {
		main := ar.Paths[0]
		if system.IsLauncher(main) {
			for _, p := range ar.Paths[1:] {
				if system.InUserWritableDir(p) {
					set(engine.Suspicious, "skript/DLL Temp yoki AppData papkasidan ishga tushiriladi")
				}
			}
			if strings.Contains(cmd, "-enc") || strings.Contains(cmd, " hidden") || strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://") || strings.Contains(cmd, "frombase64") {
				set(engine.Suspicious, "yashirin yoki internetdan yuklovchi buyruq")
			}
		} else if system.InUserWritableDir(main) && !v.Missing && ar.Kind != system.AutorunFile && !cachedTrust(main) {
			set(engine.Suspicious, "raqamli imzosiz dastur Temp/AppData/ProgramData'dan avtomatik ishga tushadi")
		}
	}
	return v
}

// visible ro'yxatda ko'rsatiladigan yozuvlar (Windows'ning o'z vazifa va xizmatlari yashiriladi).
func visible(v autorunVerdict) bool {
	if v.Severity > 0 {
		return true
	}
	switch v.Entry.Kind {
	case system.AutorunService:
		return false
	case system.AutorunTask:
		return !v.Entry.Microsoft
	}
	return true
}

// reviewAutoruns shubhali avtoyuklash yozuvlarini ko'rsatadi va o'chirishni taklif qiladi.
// onlyBad=true bo'lsa faqat muammoli yozuvlar chiqariladi. Qolgan muammoli yozuvlar sonini qaytaradi.
func (a *app) reviewAutoruns(list []system.Autorun, onlyBad bool) int {
	var bad, shown []autorunVerdict
	for _, ar := range list {
		v := a.assessAutorun(ar)
		if v.Severity > 0 {
			bad = append(bad, v)
		}
		if visible(v) {
			shown = append(shown, v)
		}
	}
	if !onlyBad {
		fmt.Println(ui.Bold(fmt.Sprintf("\n▶ Avtoyuklash dasturlari (%d ta, Windows'ning o'z xizmat va vazifalari ko'rsatilmaydi)", len(shown))))
		for i, v := range shown {
			status := ui.Green("[TOZA]    ")
			switch {
			case v.Severity == engine.Malicious:
				status = ui.Red("[XAVFLI]  ")
			case v.Severity == engine.Suspicious:
				status = ui.Yellow("[SHUBHALI]")
			case v.Entry.Disabled:
				status = ui.Dim("[O'CHIQ]  ")
			case v.Missing:
				status = ui.Dim("[FAYL YO'Q]")
			}
			fmt.Printf(" %3d. %s %s %s\n        %s\n        %s\n", i+1, status, ui.Bold(v.Entry.Name), ui.Dim("("+v.Entry.Kind.String()+")"), ui.Dim(v.Entry.Location), ui.Shorten(v.Entry.Command, 100))
			if v.Reason != "" {
				fmt.Printf("        → %s\n", v.Reason)
			}
		}
		defer func() {
			if a.action != "ask" || len(shown) == 0 {
				return
			}
			for {
				s := ui.Ask("\nBoshqa yozuvni o'chirish uchun raqamini kiriting (Enter — chiqish): ")
				n, err := strconv.Atoi(s)
				if err != nil || n < 1 || n > len(shown) {
					return
				}
				ar := shown[n-1].Entry
				if ar.Kind == system.AutorunWinlogon && !system.WinlogonModified(ar) {
					fmt.Println(ui.Yellow("Bu qiymat standart holatda."))
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
		}()
	}
	if len(bad) == 0 {
		if onlyBad {
			a.println(ui.Green("✔ Avtoyuklashda shubhali yozuv yo'q."))
		}
		return 0
	}
	a.println(ui.Red(fmt.Sprintf("\n⚠ Avtoyuklashda %d ta muammoli yozuv:", len(bad))))
	remaining := 0
	for _, v := range bad {
		a.printf("  %s %s %s — %s\n        %s\n        %s\n", sevLabel(v.Severity), ui.Bold(v.Entry.Name), ui.Dim("("+v.Entry.Kind.String()+")"), v.Reason, ui.Dim(v.Entry.Location), ui.Shorten(v.Entry.Command, 100))
		a.logLine(fmt.Sprintf("AVTOYUKLASH %s %s %s = %s (%s)", v.Severity, v.Entry.Location, v.Entry.Name, v.Entry.Command, v.Reason))
		remove := false
		switch a.action {
		case "quarantine", "delete", "auto":
			remove = v.Severity == engine.Malicious
		case "ask":
			q := "  Avtoyuklashdan o'chirilsinmi?"
			switch v.Entry.Kind {
			case system.AutorunWinlogon:
				q = "  Standart qiymat tiklansinmi?"
			case system.AutorunService:
				q = "  Xizmat o'chirib qo'yilsinmi (Start=Disabled)?"
			}
			remove = ui.Confirm(q, v.Severity == engine.Malicious)
		}
		if !remove {
			remaining++
			continue
		}
		if err := a.removeAutorun(v.Entry); err != nil {
			a.printf("  %s %v\n", ui.Red("✘"), err)
			remaining++
		} else {
			a.printf("  %s %s olib tashlandi\n", ui.Green("✔"), v.Entry.Name)
		}
	}
	return remaining
}

func (a *app) removeAutorun(ar system.Autorun) error {
	// Zaxira nusxasi: noto'g'ri o'chirilgan yozuvni qo'lda tiklash uchun.
	if f, err := os.OpenFile(filepath.Join(a.dataDir, "autoruns-backup.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\n", time.Now().Format(time.DateTime), ar.Kind, ar.Location, ar.Name, ar.Command)
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

// checkHosts hosts faylini tekshiradi; muhim saytlarni o'g'irlovchi satrlarni o'chirishni taklif qiladi.
func (a *app) checkHosts(onlyBad bool) int {
	path := system.HostsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	issues := system.CheckHosts(data)
	severe := map[int]bool{}
	for _, is := range issues {
		if is.Severe {
			severe[is.Line] = true
		}
	}
	if len(issues) == 0 || (onlyBad && len(severe) == 0) {
		if !onlyBad {
			fmt.Println(ui.Green("\n✔ hosts fayli toza."))
		}
		return 0
	}
	a.println(ui.Bold("\n▶ hosts fayli: " + path))
	for _, is := range issues {
		label := ui.Dim("[MA'LUMOT]")
		if is.Severe {
			label = ui.Red("[XAVFLI]  ")
		}
		if is.Severe || !onlyBad {
			a.printf("  %s %d-satr: %s — %s\n", label, is.Line, is.Text, is.Reason)
		}
	}
	if len(severe) == 0 {
		return 0
	}
	a.logLine(fmt.Sprintf("HOSTS %d ta xavfli satr", len(severe)))
	fix := false
	switch a.action {
	case "auto", "quarantine", "delete":
		fix = true
	case "ask":
		fix = ui.Confirm("Xavfli satrlar o'chirilsinmi (izohga aylantiriladi)?", true)
	}
	if !fix {
		return len(severe)
	}
	_ = os.WriteFile(filepath.Join(a.dataDir, "hosts.backup-"+time.Now().Format("20060102-150405")), data, 0o644)
	if err := os.WriteFile(path, system.DisableHostsLines(data, severe), 0o644); err != nil {
		a.printf("  %s hosts faylini yozib bo'lmadi: %v\n", ui.Red("✘"), err)
		return len(severe)
	}
	a.println(ui.Green("✔ hosts fayli tuzatildi (zaxira nusxasi ma'lumotlar papkasida)."))
	return 0
}

func (a *app) startupCheck() int {
	rem := a.reviewAutoruns(system.Autoruns(), false)
	rem += a.checkHosts(false)
	if rem > 0 {
		return 1
	}
	return 0
}
