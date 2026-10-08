// Package ui — konsol uchun ranglar, so'rovlar va jarayon satri.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

var color = true

// SetColor ranglarni yoqadi yoki o'chiradi.
func SetColor(on bool) { color = on }

func paint(code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Red(s string) string    { return paint("91", s) }
func Green(s string) string  { return paint("92", s) }
func Yellow(s string) string { return paint("93", s) }
func Cyan(s string) string   { return paint("96", s) }
func Bold(s string) string   { return paint("1", s) }
func Dim(s string) string    { return paint("90", s) }

var in = bufio.NewReader(os.Stdin)

// Ask savol berib, foydalanuvchi kiritgan satrni qaytaradi.
func Ask(prompt string) string {
	fmt.Print(prompt)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

// Confirm ha/yo'q savoli: "h" — ha, "y" — yo'q. Bo'sh javob — def.
func Confirm(prompt string, def bool) bool {
	hint := " [h/Y]: "
	if def {
		hint = " [H/y]: "
	}
	switch strings.ToLower(Ask(prompt + hint)) {
	case "":
		return def
	case "h", "ha":
		return true
	}
	return false
}

// Pause "Davom etish uchun Enter" kutadi.
func Pause() { Ask(Dim("\nDavom etish uchun Enter tugmasini bosing...")) }

// Clear ekranni tozalaydi.
func Clear() {
	if color {
		fmt.Print("\x1b[2J\x1b[H")
	}
}

// Status bir satrda yangilanadigan holat satrini chiqaradi.
func Status(s string) {
	const width = 100
	s = Shorten(s, width)
	fmt.Printf("\r%s%s", s, strings.Repeat(" ", max(0, width-utf8.RuneCountInString(s))))
}

// EndStatus holat satrini tozalaydi.
func EndStatus() { fmt.Printf("\r%s\r", strings.Repeat(" ", 101)) }

// Shorten uzun satrni o'rtasidan qisqartiradi.
func Shorten(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	half := (max - 3) / 2
	return string(r[:half]) + "..." + string(r[len(r)-(max-3-half):])
}

// Banner dastur sarlavhasi.
func Banner(version string) {
	const w = 58
	pad := func(s string) string {
		if n := w - utf8.RuneCountInString(s); n > 0 {
			return s + strings.Repeat(" ", n)
		}
		return s
	}
	line := strings.Repeat("═", w)
	fmt.Println(Cyan("╔" + line + "╗"))
	fmt.Println(Cyan("║") + Bold(pad(fmt.Sprintf("  QALQON ANTIVIRUS  v%s", version))) + Cyan("║"))
	fmt.Println(Cyan("║") + Dim(pad("  Kompyuter va fleshkalarni viruslardan himoya qilish")) + Cyan("║"))
	fmt.Println(Cyan("╚" + line + "╝"))
}
