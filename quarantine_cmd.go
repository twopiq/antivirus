package main

import (
	"fmt"
	"strings"

	"github.com/twopiq/antivirus/internal/ui"
)

func (a *app) printQuarantine() int {
	items, err := a.q.List()
	if err != nil {
		fmt.Println(ui.Red("Karantinni o'qib bo'lmadi: " + err.Error()))
		return -1
	}
	if len(items) == 0 {
		fmt.Println(ui.Green("Karantin bo'sh."))
		return 0
	}
	fmt.Println(ui.Bold(fmt.Sprintf("\nKarantinda %d ta fayl:", len(items))))
	for i, it := range items {
		fmt.Printf(" %3d. %s  %s\n        %s  %s\n", i+1, it.Date.Format("2006-01-02 15:04"), it.OriginalPath, ui.Red(it.Threat), ui.Dim(it.ID))
	}
	return len(items)
}

func (a *app) quarantineCmd(args []string) int {
	sub := "list"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	ref := ""
	if len(args) > 1 {
		ref = args[1]
	}
	switch sub {
	case "list", "ls":
		if a.printQuarantine() < 0 {
			return 1
		}
	case "restore":
		to := ""
		if len(args) > 2 {
			to = args[2]
		}
		dst, err := a.q.Restore(ref, to)
		if err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		fmt.Println(ui.Green("✔ Tiklandi: " + dst))
		a.logLine("KARANTINDAN TIKLANDI " + dst)
	case "delete", "rm":
		if err := a.q.Delete(ref); err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		fmt.Println(ui.Green("✔ O'chirildi"))
	case "clear":
		n, err := a.q.Clear()
		if err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		fmt.Println(ui.Green(fmt.Sprintf("✔ Karantin tozalandi (%d ta fayl)", n)))
	default:
		fmt.Println("Foydalanish: qalqon quarantine list|restore N [yo'l]|delete N|clear")
		return 2
	}
	return 0
}

func (a *app) quarantineMenu() {
	for {
		n := a.printQuarantine()
		if n <= 0 {
			return
		}
		fmt.Println("\n  1. Faylni tiklash   2. Faylni butunlay o'chirish   3. Karantinni tozalash   0. Orqaga")
		switch ui.Ask("Tanlang: ") {
		case "1":
			ref := ui.Ask("Raqami: ")
			if ui.Confirm(ui.Yellow("Fayl zararli bo'lishi mumkin. Baribir tiklansinmi?"), false) {
				a.quarantineCmd([]string{"restore", ref})
			}
		case "2":
			a.quarantineCmd([]string{"delete", ui.Ask("Raqami: ")})
		case "3":
			if ui.Confirm("Karantindagi barcha fayllar butunlay o'chirilsinmi?", false) {
				a.quarantineCmd([]string{"clear"})
			}
		default:
			return
		}
	}
}
