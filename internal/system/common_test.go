package system

import (
	"reflect"
	"strings"
	"testing"
)

func TestCommandPaths(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\ali\AppData\Roaming`)
	cases := map[string][]string{
		`"C:\Program Files\App\app.exe" --minimized`:                 {`C:\Program Files\App\app.exe`},
		`C:\Program Files\App\app.exe /background`:                   {`C:\Program Files\App\app.exe`},
		`C:\Windows\System32\wscript.exe "%APPDATA%\svc\run.vbs"`:    {`C:\Windows\System32\wscript.exe`, `C:\Users\ali\AppData\Roaming\svc\run.vbs`},
		`C:\Windows\system32\rundll32.exe C:\Users\ali\x.dll,Start`:  {`C:\Windows\system32\rundll32.exe`, `C:\Users\ali\x.dll`},
		`C:\Windows\System32\cmd.exe /c start C:\Users\Public\a.bat`: {`C:\Windows\System32\cmd.exe`, `C:\Users\Public\a.bat`},
	}
	for in, want := range cases {
		if got := CommandPaths(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s\n  kutilgan %q\n  olingan  %q", in, want, got)
		}
	}
	if !InUserWritableDir(`C:\Users\ali\AppData\Local\Temp\x.exe`) || InUserWritableDir(`C:\Program Files\x.exe`) {
		t.Error("InUserWritableDir")
	}
}

func TestTaskActions(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task><Settings><Enabled>true</Enabled></Settings><Actions Context="Author">
<Exec><Command>C:\Users\ali\AppData\Roaming\upd\run.exe</Command><Arguments>-silent</Arguments></Exec>
<Exec><Command>wscript.exe</Command><Arguments>&quot;C:\Users\Public\x.vbs&quot;</Arguments></Exec>
</Actions></Task>`
	// UTF-16LE + BOM, Windows'dagi kabi.
	b := []byte{0xFF, 0xFE}
	for _, r := range xml {
		b = append(b, byte(r), byte(r>>8))
	}
	cmds, enabled := TaskActions(b)
	if !enabled || len(cmds) != 2 || cmds[0] != `C:\Users\ali\AppData\Roaming\upd\run.exe -silent` || cmds[1] != `wscript.exe "C:\Users\Public\x.vbs"` {
		t.Fatalf("%v %q", enabled, cmds)
	}
	if _, en := TaskActions([]byte(`<Task><Settings><Enabled>false</Enabled></Settings></Task>`)); en {
		t.Fatal("o'chirilgan vazifa")
	}
}

func TestHosts(t *testing.T) {
	data := []byte("# izoh\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n10.1.1.1 printer.local\n127.0.0.1 www.kaspersky.com\n91.200.1.1 my.gov.uz click.uz\n0.0.0.0 facebook.com\n")
	issues := CheckHosts(data)
	severe, other := 0, 0
	for _, i := range issues {
		if i.Severe {
			severe++
		} else {
			other++
		}
	}
	if severe != 3 || other != 2 {
		t.Fatalf("%+v", issues)
	}
	fixed := string(DisableHostsLines(data, map[int]bool{5: true}))
	if !strings.Contains(fixed, "# Qalqon o'chirdi: 127.0.0.1 www.kaspersky.com") {
		t.Fatal(fixed)
	}
	if NormalizeDriverPath(`\SystemRoot\System32\drivers\x.sys`, `C:\Windows`) != `C:\Windows\System32\drivers\x.sys` ||
		NormalizeDriverPath(`\??\C:\x.sys`, `C:\Windows`) != `C:\x.sys` ||
		NormalizeDriverPath(`System32\drivers\y.sys`, `C:\Windows`) != `C:\Windows\System32\drivers\y.sys` {
		t.Fatal("NormalizeDriverPath")
	}
}
