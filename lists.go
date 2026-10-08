package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/sigdb"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

// allowCmd ishonchli fayllar ro'yxati: qalqon allow <fayl|sha256> | list | remove <sha256|N>
func (a *app) allowCmd(args []string) int {
	path := filepath.Join(a.store.SourcesDir(), "allow.txt")
	if len(args) == 0 || args[0] == "list" {
		lines := readLines(path)
		if len(lines) == 0 {
			fmt.Println("Ishonchli fayllar ro'yxati bo'sh.")
			return 0
		}
		fmt.Println(ui.Bold("Ishonchli fayllar (tekshiruvda e'tiborga olinmaydi):"))
		for i, l := range lines {
			fmt.Printf(" %3d. %s\n", i+1, l)
		}
		return 0
	}
	if args[0] == "remove" || args[0] == "rm" {
		if len(args) < 2 {
			fmt.Println("Foydalanish: qalqon allow remove <sha256|raqam>")
			return 2
		}
		return a.removeLine(path, args[1])
	}
	for _, target := range args {
		entry := target
		if h, _, ok := sigdb.ParseListLine(target); !ok || len(h) != 32 {
			sum, err := fileSHA256(target)
			if err != nil {
				fmt.Println(ui.Red("✘ " + err.Error()))
				return 1
			}
			abs, _ := filepath.Abs(target)
			entry = sum + " " + abs
		}
		if _, err := a.store.AppendList("allow.txt", []string{entry}); err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		fmt.Println(ui.Green("✔ Ishonchli ro'yxatga qo'shildi: " + entry))
		a.logLine("ISHONCHLI " + entry)
	}
	return 0
}

// removeLine fayldagi satrni raqami yoki matni bo'yicha o'chiradi.
func (a *app) removeLine(path, ref string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(ui.Red("✘ " + err.Error()))
		return 1
	}
	var kept, items []string
	for _, l := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			items = append(items, t)
		}
	}
	removed := ""
	for i, l := range items {
		if fmt.Sprint(i+1) == ref || strings.HasPrefix(strings.ToLower(l), strings.ToLower(ref)) || strings.EqualFold(l, ref) {
			if removed == "" {
				removed = l
				continue
			}
		}
		kept = append(kept, l)
	}
	if removed == "" {
		fmt.Println(ui.Yellow("Topilmadi: " + ref))
		return 1
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		fmt.Println(ui.Red("✘ " + err.Error()))
		return 1
	}
	fmt.Println(ui.Green("✔ O'chirildi: " + removed))
	return 0
}

// excludeCmd tekshirilmaydigan papkalar: qalqon exclude add|remove|list <yo'l>
func (a *app) excludeCmd(args []string) int {
	path := a.exclusionsPath()
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list", "ls":
		lines := readLines(path)
		if len(lines) == 0 {
			fmt.Println("Istisnolar yo'q.")
		}
		for i, l := range lines {
			fmt.Printf(" %3d. %s\n", i+1, l)
		}
	case "add":
		if len(args) < 2 {
			fmt.Println("Foydalanish: qalqon exclude add <papka yoki fayl>")
			return 2
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		for _, p := range args[1:] {
			abs, _ := filepath.Abs(p)
			fmt.Fprintln(f, abs)
			fmt.Println(ui.Green("✔ Istisnoga qo'shildi: " + abs))
		}
		f.Close()
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Println("Foydalanish: qalqon exclude remove <yo'l|raqam>")
			return 2
		}
		return a.removeLine(path, args[1])
	default:
		fmt.Println("Foydalanish: qalqon exclude add|remove|list [yo'l]")
		return 2
	}
	return 0
}

// status himoya holatini ko'rsatadi.
func (a *app) status() int {
	installed, running, tasks := protectionStatus()
	st := a.state.get()
	ok := func(b bool, yes, no string) string {
		if b {
			return ui.Green(yes)
		}
		return ui.Red(no)
	}
	fmt.Println(ui.Bold("\n▶ Himoya holati"))
	fmt.Printf("  O'rnatilgan:          %s\n", ok(installed, "ha", "yo'q (qalqon install)"))
	fmt.Printf("  Real vaqt himoyasi:   %s\n", ok(running, "ishlamoqda", "o'chiq"))
	names := make([]string, 0, len(tasks))
	for n := range tasks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("  Vazifa %-18s %s\n", n+":", ok(tasks[n], "bor", "yo'q"))
	}
	ver := a.store.CurrentVersion()
	age := "—"
	fresh := false
	if t, err := time.ParseInLocation("20060102-150405", ver[:min(len(ver), 15)], time.Local); err == nil {
		age = ago(t)
		fresh = time.Since(t) < 3*24*time.Hour
	}
	fmt.Printf("  Virus bazasi:         %s ta imzo, %s\n", sigdb.FormatCount(a.signatureCount()), ok(fresh, "yangilangan "+age, "eskirgan ("+age+") — qalqon update"))
	fmt.Printf("  Oxirgi yangilash:     %s\n", ago(st.LastUpdate))
	fmt.Printf("  Tezkor tekshiruv:     %s\n", ago(st.LastQuick))
	fmt.Printf("  To'liq tekshiruv:     %s\n", ago(st.LastFull))
	fmt.Printf("  Karantin:             %d ta fayl\n", a.quarantineCount())
	fmt.Printf("  Administrator:        %s\n", ok(system.IsAdmin(), "ha", "yo'q"))
	if installed && running && fresh {
		fmt.Println(ui.Green("\n✔ Kompyuteringiz himoyalangan."))
		return 0
	}
	fmt.Println(ui.Yellow("\n! Himoya to'liq emas."))
	return 1
}
