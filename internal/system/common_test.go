package system

import (
	"reflect"
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
