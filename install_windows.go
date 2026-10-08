//go:build windows

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/twopiq/antivirus/internal/system"
	"github.com/twopiq/antivirus/internal/ui"
)

const (
	taskProtect = `\Qalqon\Himoya`
	taskUpdate  = `\Qalqon\Yangilash`
	taskScan    = `\Qalqon\Tekshiruv`
	uninstKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Qalqon`
)

func installDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Qalqon")
}

func xmlEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// taskXML Task Scheduler vazifasi ta'rifini quradi.
func taskXML(desc, trigger, principal, limit, exe, args string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Qalqon Antivirus</Author><Description>` + xmlEsc(desc) + `</Description></RegistrationInfo>
  <Triggers>` + trigger + `</Triggers>
  <Principals><Principal id="Author">` + principal + `<RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowHardTerminate>true</AllowHardTerminate>
    <ExecutionTimeLimit>` + limit + `</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEsc(exe) + `</Command><Arguments>` + xmlEsc(args) + `</Arguments></Exec></Actions>
</Task>`
}

func createTask(name, def string) error {
	u := utf16.Encode([]rune(def))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qalqon-task-%d.xml", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	out, err := exec.Command("schtasks.exe", "/Create", "/TN", name, "/XML", tmp, "/F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

func taskExists(name string) bool {
	return exec.Command("schtasks.exe", "/Query", "/TN", name).Run() == nil
}

// otherInstances shu dasturning boshqa nusxalari (masalan fondagi himoya).
func otherInstances() []system.Proc {
	procs, _ := system.Processes()
	self := uint32(os.Getpid())
	var out []system.Proc
	for _, p := range procs {
		if p.PID != self && strings.EqualFold(p.Name, "qalqon.exe") {
			out = append(out, p)
		}
	}
	return out
}

func stopProtection() {
	_ = exec.Command("schtasks.exe", "/End", "/TN", taskProtect).Run()
	for _, p := range otherInstances() {
		_ = system.KillProcess(p.PID)
	}
	time.Sleep(500 * time.Millisecond)
}

func startDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	return cmd.Start()
}

func (a *app) install() int {
	if !system.IsAdmin() {
		fmt.Println(ui.Red("O'rnatish uchun administrator huquqi kerak."))
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Println(ui.Red(err.Error()))
		return 1
	}
	dir := installDir()
	dst := filepath.Join(dir, "qalqon.exe")
	fmt.Println(ui.Bold("\n▶ Qalqon o'rnatilmoqda: " + dir))
	stopProtection()
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(dst)) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Println(ui.Red("✘ " + err.Error()))
			return 1
		}
		if err := copyFile(self, dst); err != nil {
			fmt.Println(ui.Red("✘ Faylni nusxalab bo'lmadi: " + err.Error()))
			return 1
		}
	}
	fmt.Println(ui.Green("  ✔ dastur nusxalandi"))

	if err := secureDataDir(a.dataDir); err != nil {
		fmt.Println(ui.Yellow("  ! ma'lumotlar papkasi ruxsatlarini o'rnatib bo'lmadi: " + err.Error()))
	} else {
		fmt.Println(ui.Green("  ✔ sozlamalar va baza oddiy dasturlar o'zgartira olmaydigan qilib himoyalandi"))
	}

	today := time.Now().Format("2006-01-02")
	tasks := []struct{ name, def, desc string }{
		{taskProtect, taskXML("Qalqon real vaqt himoyasi", `<LogonTrigger><Enabled>true</Enabled></LogonTrigger>`,
			`<GroupId>S-1-5-32-545</GroupId>`, "PT0S", dst, "protect --background"), "real vaqt himoyasi (har bir kirishda)"},
		{taskUpdate, taskXML("Qalqon virus bazasini yangilash",
			`<CalendarTrigger><StartBoundary>`+today+`T09:00:00</StartBoundary><Repetition><Interval>PT6H</Interval><Duration>P1D</Duration></Repetition><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger><BootTrigger><Delay>PT15M</Delay></BootTrigger>`,
			`<UserId>S-1-5-18</UserId>`, "PT2H", dst, "update --quiet"), "bazani yangilash (har 6 soatda)"},
		{taskScan, taskXML("Qalqon haftalik tezkor tekshiruv",
			`<CalendarTrigger><StartBoundary>`+today+`T13:00:00</StartBoundary><ScheduleByWeek><DaysOfWeek><Wednesday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>`,
			`<UserId>S-1-5-18</UserId>`, "PT6H", dst, "quick --action auto --quiet"), "haftalik tezkor tekshiruv (chorshanba)"},
	}
	ok := true
	for _, t := range tasks {
		if err := createTask(t.name, t.def); err != nil {
			fmt.Println(ui.Red("  ✘ " + err.Error()))
			ok = false
			continue
		}
		fmt.Println(ui.Green("  ✔ vazifa: " + t.desc))
	}
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstKey, registry.SET_VALUE); err == nil {
		k.SetStringValue("DisplayName", "Qalqon Antivirus")
		k.SetStringValue("DisplayVersion", version)
		k.SetStringValue("Publisher", "Qalqon")
		k.SetStringValue("DisplayIcon", dst)
		k.SetStringValue("InstallLocation", dir)
		k.SetStringValue("UninstallString", `"`+dst+`" uninstall`)
		k.SetDWordValue("NoModify", 1)
		k.SetDWordValue("NoRepair", 1)
		k.Close()
		fmt.Println(ui.Green("  ✔ \"Dasturlar va imkoniyatlar\" ro'yxatiga qo'shildi"))
	}
	if err := startDetached(dst, "protect", "--background"); err == nil {
		fmt.Println(ui.Green("  ✔ real vaqt himoyasi ishga tushirildi"))
	}
	if a.store.CurrentVersion() == "" {
		fmt.Println(ui.Yellow("  Virus bazasi hali yuklanmagan — hozir yuklanadi..."))
		a.update(updateOpts{source: "all"})
	}
	a.logLine("O'RNATILDI " + dst)
	if ok {
		fmt.Println(ui.Green("\n✔ Qalqon o'rnatildi. Himoya har safar Windows'ga kirganingizda avtomatik ishga tushadi."))
		fmt.Println(ui.Dim("  Dasturni ochish: " + dst))
		return 0
	}
	return 1
}

func (a *app) uninstall(purge bool) int {
	if !system.IsAdmin() {
		fmt.Println(ui.Red("O'chirish uchun administrator huquqi kerak."))
		return 1
	}
	fmt.Println(ui.Bold("\n▶ Qalqon o'chirilmoqda"))
	stopProtection()
	for _, t := range []string{taskProtect, taskUpdate, taskScan} {
		_ = exec.Command("schtasks.exe", "/Delete", "/TN", t, "/F").Run()
	}
	_ = exec.Command("schtasks.exe", "/Delete", "/TN", `\Qalqon`, "/F").Run()
	fmt.Println(ui.Green("  ✔ rejalashtirilgan vazifalar o'chirildi"))
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, uninstKey)
	dir := installDir()
	self, _ := os.Executable()
	if strings.HasPrefix(strings.ToLower(self), strings.ToLower(dir)+`\`) {
		// O'zini o'chira olmaydi — jarayon tugagach cmd o'chiradi.
		_ = exec.Command("cmd.exe", "/C", "ping 127.0.0.1 -n 3 > nul & rmdir /s /q \""+dir+"\"").Start()
	} else {
		_ = os.RemoveAll(dir)
	}
	fmt.Println(ui.Green("  ✔ dastur fayllari o'chirildi"))
	if purge {
		if items, _ := a.q.List(); len(items) > 0 {
			fmt.Println(ui.Yellow(fmt.Sprintf("  Karantinda %d ta fayl bor — ular ham o'chiriladi.", len(items))))
		}
		_ = os.RemoveAll(a.dataDir)
		fmt.Println(ui.Green("  ✔ ma'lumotlar (baza, karantin, jurnallar) o'chirildi"))
	} else {
		fmt.Println(ui.Dim("  Ma'lumotlar saqlab qolindi: " + a.dataDir + " (o'chirish uchun: uninstall --purge)"))
	}
	fmt.Println(ui.Green("\n✔ Qalqon o'chirildi."))
	return 0
}

// protectionStatus o'rnatilganlik va himoya holati.
func protectionStatus() (installed, running bool, tasks map[string]bool) {
	tasks = map[string]bool{}
	for _, t := range []string{taskProtect, taskUpdate, taskScan} {
		tasks[t] = taskExists(t)
	}
	installed = tasks[taskProtect]
	running = len(otherInstances()) > 0 && !system.SingleInstanceFree("QalqonHimoya")
	return
}

// secureDataDir ma'lumotlar papkasi ruxsatlarini cheklaydi: zararli dastur oddiy
// foydalanuvchi huquqi bilan o'zini ishonchli ro'yxatga yoki istisnolarga yoza olmasin.
// Foydalanuvchilar faqat jurnallar va karantinga yoza oladi (real vaqt himoyasi uchun).
func secureDataDir(dir string) error {
	for _, d := range []string{dir, filepath.Join(dir, "logs"), filepath.Join(dir, "Quarantine"), filepath.Join(dir, "sources")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	run := func(args ...string) error {
		out, err := exec.Command("icacls.exe", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("icacls: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	// SYSTEM va Administratorlar — to'liq, Foydalanuvchilar — faqat o'qish.
	if err := run(dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/C", "/Q"); err != nil {
		return err
	}
	for _, d := range []string{"logs", "Quarantine"} {
		if err := run(filepath.Join(dir, d), "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q"); err != nil {
			return err
		}
	}
	return nil
}
