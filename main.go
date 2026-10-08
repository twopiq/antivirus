// Qalqon — Windows uchun antivirus dasturi (konsol).
//
// Ishga tushirish:
//
//	qalqon.exe                 — interaktiv menyu
//	qalqon.exe install         — o'rnatish (real vaqt himoyasi, avtomatik yangilanish)
//	qalqon.exe quick           — tezkor tekshiruv
//	qalqon.exe full            — barcha disklarni tekshirish
//	qalqon.exe help            — barcha buyruqlar
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/twopiq/antivirus/internal/sigdb"
	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

const version = "2.0.0"

func usage() {
	fmt.Printf(`Qalqon Antivirus v%s — kompyuter va fleshkalarni viruslardan himoya qilish

Foydalanish:
  qalqon                         interaktiv menyu (sichqoncha bilan ikki marta bosilganda)

 Himoya:
  qalqon install                 o'rnatish: real vaqt himoyasi, har 6 soatda baza yangilash,
                                 haftalik tekshiruv (Task Scheduler orqali)
  qalqon uninstall [--purge]     o'chirish (--purge — baza va karantin ham)
  qalqon status                  himoya holati
  qalqon protect                 real vaqt himoyasini shu oynada ishga tushirish

 Tekshiruv:
  qalqon quick                   tezkor: jarayonlar va DLL'lar, avtoyuklash, vazifalar, xizmatlar,
                                 hosts fayli, Yuklamalar, Ish stoli, Temp, AppData
  qalqon full                    barcha disklarni to'liq tekshirish
  qalqon scan <yo'l> [yo'l...]   tanlangan fayl yoki papkalarni tekshirish
  qalqon usb [disk]              fleshkani tekshirish, yorliq virusidan tozalash, yashirilgan fayllarni tiklash
  qalqon startup                 avtoyuklash, vazifalar, xizmatlar, IFEO va hosts faylini ko'rish
  qalqon processes               ishlab turgan jarayonlarni tekshirish

 Baza:
  qalqon update                  ClamAV va MalwareBazaar bazalarini yangilash
        --source all|clamav|bazaar   faqat bitta manba
        --full                       MalwareBazaar to'liq bazasi (oxirgi 48 soat o'rniga)
        --file F                     fayldan import: main.cvd, daily.cvd, *.hdb, *.hsb, *.ndb, xeshlar.txt
        --url U                      boshqa xeshlar ro'yxatidan yuklash
        --force                      kutish vaqtiga qaramay yuklash va qayta kompilyatsiya qilish
  qalqon quarantine list|restore N|delete N|clear
  qalqon allow <fayl|sha256>     faylni ishonchli deb belgilash (noto'g'ri aniqlanganda)
  qalqon allow list|remove N
  qalqon exclude add|remove|list <yo'l>
                                 tekshirilmaydigan papkalar
  qalqon version                 versiya va baza haqida ma'lumot

Tekshiruv sozlamalari (buyruqdan keyin yoziladi):
  --action ask|auto|report|quarantine|delete
                    ask — so'rash (standart), auto — XAVFLI fayllarni karantinga, shubhalilar haqida
                    xabar berish, report — faqat hisobot, quarantine — hammasini karantinga
  --yes             = --action quarantine
  --quiet           faqat natijalar (rejalashtirilgan vazifalar uchun)
  --no-cache        o'zgarmagan fayllarni ham qayta tekshirish
  --workers N       parallel oqimlar soni
  --max-size MB     mazmuni tekshiriladigan eng katta fayl hajmi (standart 50)
  --no-color        ranglarsiz chiqish

Ma'lumotlar papkasi: %s
`, version, system.DataDir())
}

func main() {
	colorOK := system.InitConsole()
	ui.SetColor(colorOK && os.Getenv("NO_COLOR") == "")

	if len(os.Args) < 2 {
		os.Exit(runInteractive())
	}
	cmd := strings.ToLower(strings.TrimLeft(os.Args[1], "-/"))
	args := os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	action := fs.String("action", "ask", "ask|auto|report|quarantine|delete")
	yes := fs.Bool("yes", false, "so'ramasdan karantinga o'tkazish")
	quiet := fs.Bool("quiet", false, "faqat natijalar")
	noCache := fs.Bool("no-cache", false, "keshsiz tekshirish")
	workers := fs.Int("workers", 0, "parallel oqimlar soni")
	maxSize := fs.Int64("max-size", 50, "eng katta fayl hajmi, MB")
	noColor := fs.Bool("no-color", false, "ranglarsiz")
	full := fs.Bool("full", false, "update: to'liq MalwareBazaar bazasi")
	file := fs.String("file", "", "update: fayldan import")
	url := fs.String("url", "", "update: boshqa manzildan yuklash")
	source := fs.String("source", "all", "update: all|clamav|bazaar")
	force := fs.Bool("force", false, "update: majburiy yangilash")
	background := fs.Bool("background", false, "protect: fon rejimi (oynasiz)")
	purge := fs.Bool("purge", false, "uninstall: ma'lumotlarni ham o'chirish")
	fs.Usage = usage
	_ = fs.Parse(reorderFlags(args))
	if *noColor || *quiet {
		ui.SetColor(false)
	}
	if *yes {
		*action = "quarantine"
	}
	switch *action {
	case "ask", "auto", "report", "quarantine", "delete":
	default:
		fmt.Fprintln(os.Stderr, "Noto'g'ri --action qiymati:", *action)
		os.Exit(2)
	}
	switch *source {
	case "all", "clamav", "bazaar":
	default:
		fmt.Fprintln(os.Stderr, "Noto'g'ri --source qiymati:", *source)
		os.Exit(2)
	}

	app, err := newApp(*action, *workers, *maxSize)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Red("Xato: "+err.Error()))
		os.Exit(1)
	}
	app.quiet = *quiet
	app.useCache = !*noCache
	needAdmin := map[string]bool{"quick": true, "full": true, "usb": true, "startup": true, "processes": true, "protect": true}
	if needAdmin[cmd] && !system.IsAdmin() && !*quiet {
		fmt.Println(ui.Yellow("Diqqat: dastur administrator huquqisiz ishlamoqda — ba'zi fayllar va jarayonlarni tekshirib/o'chirib bo'lmasligi mumkin."))
	}

	code := 0
	switch cmd {
	case "quick":
		code = app.quickScan()
	case "full":
		code = app.fullScan()
	case "scan":
		if fs.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Tekshiriladigan fayl yoki papkani ko'rsating: qalqon scan C:\\Users\\Ali\\Downloads")
			os.Exit(2)
		}
		code = app.customScan(fs.Args())
	case "usb":
		code = app.usbScan(fs.Args())
	case "startup", "autorun", "autoruns":
		code = app.startupCheck()
	case "processes", "ps":
		code = app.processScan()
	case "protect", "monitor", "watch":
		code = app.protect(*background)
	case "update":
		code = app.update(updateOpts{source: *source, full: *full, file: *file, url: *url, force: *force})
	case "quarantine", "q":
		code = app.quarantineCmd(fs.Args())
	case "allow":
		code = app.allowCmd(fs.Args())
	case "exclude":
		code = app.excludeCmd(fs.Args())
	case "install":
		code = app.install()
	case "uninstall":
		code = app.uninstall(*purge)
	case "status":
		code = app.status()
	case "version":
		app.printVersion()
	case "help", "h", "?":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "Noma'lum buyruq:", os.Args[1])
		usage()
		code = 2
	}
	os.Exit(code)
}

// reorderFlags bayroqlarni pozitsion argumentlardan oldinga o'tkazadi, shunda
// "qalqon scan D:\ --yes" ham ishlaydi.
func reorderFlags(args []string) []string {
	withValue := map[string]bool{"action": true, "workers": true, "max-size": true, "file": true, "url": true, "source": true}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if withValue[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func runInteractive() int {
	if !system.IsAdmin() {
		fmt.Println(ui.Yellow("Qalqon administrator huquqi bilan to'liq ishlaydi. Ruxsat so'ralmoqda..."))
		if err := system.Elevate(nil); err == nil {
			return 0
		}
		fmt.Println(ui.Yellow("Administrator huquqi olinmadi — cheklangan rejimda davom etilmoqda."))
	}
	app, err := newApp("ask", 0, 50)
	if err != nil {
		fmt.Println(ui.Red("Xato: " + err.Error()))
		ui.Pause()
		return 1
	}
	if app.store.CurrentVersion() == "" {
		ui.Banner(version)
		fmt.Println(ui.Yellow("\nVirus bazasi hali yuklanmagan. Ishonchli himoya uchun uni yuklash kerak (ClamAV + MalwareBazaar)."))
		if ui.Confirm("Hozir yuklaymizmi?", true) {
			app.update(updateOpts{source: "all"})
			ui.Pause()
		}
	}
	for {
		ui.Clear()
		ui.Banner(version)
		installed, running, _ := protectionStatus()
		prot := ui.Red("O'CHIQ")
		switch {
		case running:
			prot = ui.Green("YOQILGAN")
		case installed:
			prot = ui.Yellow("o'rnatilgan, lekin ishlamayapti")
		}
		fmt.Printf("  Real vaqt himoyasi: %s   Baza: %s ta imzo   Karantin: %d\n\n", prot, ui.Bold(sigdb.FormatCount(app.signatureCount())), app.quarantineCount())
		items := []string{
			"Tezkor tekshiruv (jarayonlar, avtoyuklash, Yuklamalar, Temp)",
			"To'liq tekshiruv (barcha disklar)",
			"Papka yoki faylni tekshirish",
			"Fleshkani tekshirish va tozalash (USB)",
			"Avtoyuklash, xizmatlar, vazifalar va hosts fayli",
			"Ishlab turgan jarayonlarni tekshirish",
			"Karantin",
			"Virus bazasini yangilash",
			"Real vaqt himoyasi (shu oynada)",
			"Himoya holati / o'rnatish / o'chirish",
			"Ishonchli fayllar va istisnolar",
		}
		for i, it := range items {
			fmt.Printf("  %s %s\n", ui.Cyan(fmt.Sprintf("%2d.", i+1)), it)
		}
		fmt.Printf("  %s %s\n\n", ui.Cyan(" 0."), "Chiqish")
		switch ui.Ask("Tanlang: ") {
		case "1":
			app.quickScan()
		case "2":
			app.fullScan()
		case "3":
			p := strings.Trim(ui.Ask("Fayl yoki papka yo'lini kiriting (sudrab tashlash mumkin): "), `"' `)
			if p != "" {
				app.customScan([]string{p})
			}
		case "4":
			app.usbScan(nil)
		case "5":
			app.startupCheck()
		case "6":
			app.processScan()
		case "7":
			app.quarantineMenu()
		case "8":
			full := ui.Confirm("MalwareBazaar to'liq bazasini yuklaymizmi? (katta hajm; yo'q bo'lsa oxirgi 48 soat)", false)
			app.update(updateOpts{source: "all", full: full})
		case "9":
			app.protect(false)
		case "10":
			app.status()
			fmt.Println("\n  1. O'rnatish / qayta o'rnatish   2. O'chirish   0. Orqaga")
			switch ui.Ask("Tanlang: ") {
			case "1":
				app.install()
			case "2":
				if ui.Confirm(ui.Red("Qalqon o'chirilsinmi?"), false) {
					app.uninstall(ui.Confirm("Baza va karantin ham o'chirilsinmi?", false))
				}
			}
		case "11":
			app.allowCmd([]string{"list"})
			fmt.Println()
			app.excludeCmd([]string{"list"})
			fmt.Println("\n  1. Faylni ishonchli deb belgilash   2. Ishonchlilardan o'chirish")
			fmt.Println("  3. Papkani istisnoga qo'shish        4. Istisnoni o'chirish   0. Orqaga")
			switch ui.Ask("Tanlang: ") {
			case "1":
				if p := strings.Trim(ui.Ask("Fayl yo'li: "), `"' `); p != "" {
					app.allowCmd([]string{p})
				}
			case "2":
				app.allowCmd([]string{"remove", ui.Ask("Raqami: ")})
			case "3":
				if p := strings.Trim(ui.Ask("Papka yo'li: "), `"' `); p != "" {
					app.excludeCmd([]string{"add", p})
				}
			case "4":
				app.excludeCmd([]string{"remove", ui.Ask("Raqami: ")})
			}
		case "0", "q", "exit":
			return 0
		default:
			continue
		}
		ui.Pause()
	}
}
