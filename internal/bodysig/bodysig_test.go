package bodysig

import "testing"

func TestPatterns(t *testing.T) {
	data := []byte("xxHEADER--payload-1234-MALWARE_CORE!!tail")
	cases := []struct {
		sig  string
		want bool
	}{
		{"4d414c57415245", true},           // MALWARE
		{"4d414c574152455f434f5245", true}, // MALWARE_CORE
		{"48454144??52", true},
		{"4845414445522d2d*4d414c57415245", true}, // HEADER--*MALWARE
		{"4845414445522d2d{5-20}31323334", true},  // HEADER--{5-20}1234
		{"4845414445522d2d{1-3}31323334", false},  // oraliq juda kichik
		{"4845414445522d2d7061796c6f6164[1-2]31323334", true},
		{"(41|4d)414c57415245", true}, // muqobil
		{"(41|42)414c57415245", false},
		{"4?414c57415245", true}, // yarim bayt
		{"?d414c57415245", true},
		{"5?414c57415245", false},
		{"4d414c57415245{-1}434f5245", true}, // MALWARE{-1}CORE -> "_" ni o'tkazadi
		{"31323334??4d414c5741", true},
		{"31323334{2}4d414c5741", false},
	}
	for _, c := range cases {
		s, err := Compile("t", TargetAny, offset{kind: offAny}, c.sig)
		if err != nil {
			if c.want {
				t.Errorf("%s: %v", c.sig, err)
			}
			continue
		}
		if got := s.Match(data, FileInfo{EP: -1}); got != c.want {
			t.Errorf("%s: kutilgan %v, olingan %v", c.sig, c.want, got)
		}
	}
}

func TestOffsetsAndMatcher(t *testing.T) {
	data := []byte("MZ....PE..EPCODE_HERE....SIGNATURE_AT_END")
	lines := []string{
		"Test.Abs:0:0:4d5a2e2e2e2e5045",        // boshida
		"Test.AbsWrong:0:1:4d5a2e2e2e2e5045",   // noto'g'ri siljish
		"Test.Shift:0:2,5:2e2e50452e2e",        // 4 da, [2..7] ichida
		"Test.EOF:0:EOF-16:5349474e4154555245", // oxiridan 16
		"Test.EP:1:EP+0:4550434f",              // EP siljishi 10
		"Test.EPWrong:1:EP+1:4550434f",
		"Test.PEOnly:1:*:434f44455f48455245",
		"Test.Unsupported:0:*:!(41424344)45464748",
		"Test.Section:0:S1+0:41424344",
		"Test.Html:3:*:41424344",
	}
	m := NewMatcher()
	var skipped int
	for _, l := range lines {
		s, err := ParseLine(l)
		if err != nil {
			skipped++
			continue
		}
		m.Add(s)
	}
	if skipped != 3 {
		t.Fatalf("o'tkazilgan imzolar: %d", skipped)
	}
	got := map[string]bool{}
	for _, n := range m.Scan(data, FileInfo{Type: TargetPE, EP: 10}) {
		got[n] = true
	}
	for _, want := range []string{"Test.Abs", "Test.Shift", "Test.EOF", "Test.EP", "Test.PEOnly"} {
		if !got[want] {
			t.Errorf("%s topilmadi: %v", want, got)
		}
	}
	for _, no := range []string{"Test.AbsWrong", "Test.EPWrong"} {
		if got[no] {
			t.Errorf("%s noto'g'ri topildi", no)
		}
	}
	// PE bo'lmagan faylda PE imzolari ishlamasligi kerak.
	for _, n := range m.Scan(data, FileInfo{Type: TargetAny, EP: -1}) {
		if n == "Test.PEOnly" || n == "Test.EP" {
			t.Errorf("%s PE bo'lmagan faylda topildi", n)
		}
	}
}
