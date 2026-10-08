// Qalqon — Windows uchun konsol antivirus dasturi.
//
// Ishga tushirish:
//
//	qalqon.exe                 — interaktiv menyu
//	qalqon.exe quick           — tezkor tekshiruv
//	qalqon.exe full            — barcha disklarni tekshirish
//	qalqon.exe scan <yo'l>...  — tanlangan fayl/papkalarni tekshirish
//	qalqon.exe usb [E:\]       — fleshkani tekshirish va tozalash
//	qalqon.exe help            — barcha buyruqlar
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

const version = "1.0.0"

func usage() {
	fmt.Printf(`Qalqon Antivirus v%s — kompyuter va fleshkalarni viruslardan tozalash vositasi

Foydalanish:
  qalqon                         interaktiv menyu (sichqoncha bilan ikki marta bosilganda)
  qalqon quick                   tezkor tekshiruv: jarayonlar, avtoyuklash, Yuklamalar, Ish stoli, Temp
  qalqon full                    barcha disklarni to'liq tekshirish
  qalqon scan <yo'l> [yo'l...]   tanlangan fayl yoki papkalarni tekshirish
  qalqon usb [disk]              fleshkani tekshirish, yorliq (shortcut) virusidan tozalash,
                                 yashirilgan fayllarni tiklash (disk ko'rsatilmasa — barcha fleshkalar)
  qalqon startup                 avtoyuklash dasturlarini ko'rish va tekshirish
  qalqon processes               ishlab turgan jarayonlarni tekshirish
  qalqon monitor                 real vaqt kuzatuvi: yangi fayllar va ulangan fleshkalar
  qalqon update [--full] [--file F] [--url U]
                                 virus bazasini yangilash (MalwareBazaar, abuse.ch)
  qalqon quarantine list|restore N|delete N|clear
                                 karantin bilan ishlash
  qalqon version                 versiya va baza haqida ma'lumot

Tekshiruv sozlamalari (buyruqdan keyin yoziladi):
  --action ask|report|quarantine|delete
                    topilgan tahdidlar bilan nima qilish (standart: ask — so'rash)
  --yes             barcha tahdidlarni so'ramasdan karantinga o'tkazish (= --action quarantine)
  --workers N       parallel oqimlar soni
  --max-size MB     mazmuni tekshiriladigan eng katta fayl hajmi (standart 50)
  --no-color        ranglarsiz chiqish

Ma'lumotlar papkasi: %s
(virus bazasi, karantin, jurnallar; QALQON_HOME o'zgaruvchisi bilan o'zgartirish mumkin)
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
	action := fs.String("action", "ask", "ask|report|quarantine|delete")
	yes := fs.Bool("yes", false, "so'ramasdan karantinga o'tkazish")
	workers := fs.Int("workers", 0, "parallel oqimlar soni")
	maxSize := fs.Int64("max-size", 50, "eng katta fayl hajmi, MB")
	noColor := fs.Bool("no-color", false, "ranglarsiz")
	full := fs.Bool("full", false, "update: to'liq bazani yuklash")
	file := fs.String("file", "", "update: mahalliy xeshlar faylidan import qilish")
	url := fs.String("url", "", "update: boshqa manzildan yuklash")
	fs.Usage = usage
	_ = fs.Parse(reorderFlags(args))
	if *noColor {
		ui.SetColor(false)
	}
	if *yes {
		*action = "quarantine"
	}
	switch *action {
	case "ask", "report", "quarantine", "delete":
	default:
		fmt.Fprintln(os.Stderr, "Noto'g'ri --action qiymati:", *action)
		os.Exit(2)
	}

	app, err := newApp(*action, *workers, *maxSize)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Red("Xato: "+err.Error()))
		os.Exit(1)
	}
	needAdmin := map[string]bool{"quick": true, "full": true, "usb": true, "startup": true, "processes": true, "monitor": true}
	if needAdmin[cmd] && !system.IsAdmin() {
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
	case "monitor", "watch":
		code = app.monitor()
	case "update":
		code = app.update(*url, *file, *full)
	case "quarantine", "q":
		code = app.quarantineCmd(fs.Args())
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
	withValue := map[string]bool{"action": true, "workers": true, "max-size": true, "file": true, "url": true}
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
	for {
		ui.Clear()
		ui.Banner(version)
		fmt.Printf("  Virus bazasi: %s ta imzo   Karantin: %d ta fayl\n\n", ui.Bold(fmt.Sprint(app.eng.DB.Len())), app.quarantineCount())
		items := []string{
			"Tezkor tekshiruv (jarayonlar, avtoyuklash, Yuklamalar, Temp)",
			"To'liq tekshiruv (barcha disklar)",
			"Papka yoki faylni tekshirish",
			"Fleshkani tekshirish va tozalash (USB)",
			"Avtoyuklash dasturlari",
			"Ishlab turgan jarayonlarni tekshirish",
			"Karantin",
			"Virus bazasini yangilash",
			"Real vaqt kuzatuvi (monitor)",
		}
		for i, it := range items {
			fmt.Printf("  %s %s\n", ui.Cyan(fmt.Sprintf("%d.", i+1)), it)
		}
		fmt.Printf("  %s %s\n\n", ui.Cyan("0."), "Chiqish")
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
			full := ui.Confirm("To'liq bazani yuklaysizmi? (katta hajm; yo'q bo'lsa oxirgi 48 soat)", false)
			app.update("", "", full)
		case "9":
			app.monitor()
		case "0", "q", "exit":
			return 0
		default:
			continue
		}
		ui.Pause()
	}
}
