package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/sigdb"
	"github.com/twopiq/antivirus/internal/ui"
)

const (
	bazaarRecent  = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
	bazaarFull    = "https://bazaar.abuse.ch/export/txt/sha256/full/"
	clamavMirror  = "https://database.clamav.net"
	clamavDNS     = "current.cvd.clamav.net"
	clamavMinWait = 4 * time.Hour
)

type updateOpts struct {
	source string // all | bazaar | clamav
	full   bool
	file   string
	url    string
	force  bool
}

// update virus bazasini yangilaydi va qayta kompilyatsiya qiladi.
func (a *app) update(o updateOpts) int {
	if err := os.MkdirAll(a.store.SourcesDir(), 0o755); err != nil {
		fmt.Println(ui.Red("Xato: " + err.Error()))
		return 1
	}
	changed, okCount, failCount, blocked := false, 0, 0, false
	report := func(name string, ch bool, err error) {
		switch {
		case err != nil:
			failCount++
			blocked = blocked || errors.Is(err, errCDNBlocked)
			a.println(ui.Red(fmt.Sprintf("  ✘ %s: %v", name, err)))
			a.logLine(fmt.Sprintf("YANGILASH XATO %s: %v", name, err))
		default:
			okCount++
			changed = changed || ch
		}
	}
	switch {
	case o.file != "":
		ch, err := a.importFile(o.file)
		report(filepath.Base(o.file), ch, err)
	case o.url != "":
		ch, err := a.updateList(o.url, "url-"+hostOf(o.url)+".txt")
		report(o.url, ch, err)
	default:
		if o.source == "all" || o.source == "clamav" {
			ch, err := a.updateClamAV(o.force)
			report("ClamAV", ch, err)
		}
		if o.source == "all" || o.source == "bazaar" {
			u := bazaarRecent
			if o.full {
				u = bazaarFull
			}
			ch, err := a.updateList(u, "bazaar.txt")
			report("MalwareBazaar", ch, err)
		}
	}
	if a.store.CurrentVersion() == "" && len(a.store.Sources()) > 0 {
		changed = true
	}
	if changed || o.force {
		if len(a.store.Sources()) == 0 {
			a.println(ui.Yellow("Manba fayllar yo'q — baza kompilyatsiya qilinmadi."))
			return 1
		}
		a.println("Baza kompilyatsiya qilinmoqda (bir necha daqiqa olishi mumkin)...")
		st, err := a.store.Rebuild(func(s string) {
			if !a.quiet {
				ui.Status("  " + s)
			}
		})
		if !a.quiet {
			ui.EndStatus()
		}
		if err != nil {
			a.println(ui.Red("✘ Bazani kompilyatsiya qilib bo'lmadi: " + err.Error()))
			a.logLine("BAZA KOMPILYATSIYA XATO " + err.Error())
			return 1
		}
		if err := a.reloadEngine(); err != nil {
			a.println(ui.Red("✘ " + err.Error()))
			return 1
		}
		a.println(ui.Green(fmt.Sprintf("✔ Baza yangilandi: %s ta imzo (xesh %s, PE bo'lim %s, tana %s; qo'llab-quvvatlanmagan tana imzolari: %s)",
			sigdb.FormatCount(st.Total()), sigdb.FormatCount(st.Hashes), sigdb.FormatCount(st.Sections), sigdb.FormatCount(st.Body), sigdb.FormatCount(st.BodySkipped))))
		a.logLine(fmt.Sprintf("BAZA YANGILANDI %d imzo, manbalar: %s", st.Total(), strings.Join(st.Sources, ", ")))
	} else if okCount > 0 {
		a.println(ui.Green("✔ Baza allaqachon eng so'nggi holatda."))
	}
	if okCount > 0 {
		a.state.set(func(s *appState) { s.LastUpdate = time.Now() })
	}
	if okCount == 0 && failCount > 0 {
		if blocked {
			return 1
		}
		a.println(ui.Dim("Internet aloqasini tekshiring. Bazani boshqa kompyuterda yuklab, \"qalqon update --file main.cvd\" bilan import qilish ham mumkin."))
		return 1
	}
	return 0
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return strings.ReplaceAll(p.Host, ":", "_")
	}
	return "custom"
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Minute} }

func newRequest(u string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Qalqon-Antivirus/"+version)
	return req, nil
}

// updateList xeshlar ro'yxatini (MalwareBazaar yoki boshqa) yuklab, manbaga qo'shadi.
func (a *app) updateList(u, file string) (bool, error) {
	a.println("Yuklanmoqda: " + u)
	req, err := newRequest(u)
	if err != nil {
		return false, err
	}
	if k := os.Getenv("QALQON_ABUSE_KEY"); k != "" && strings.Contains(u, "abuse.ch") {
		req.Header.Set("Auth-Key", k)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return false, fmt.Errorf("server javobi: %s (abuse.ch kaliti kerak bo'lishi mumkin: QALQON_ABUSE_KEY)", resp.Status)
		}
		return false, fmt.Errorf("server javobi: %s", resp.Status)
	}
	data, err := a.readWithProgress(resp.Body, resp.ContentLength)
	if err != nil {
		return false, err
	}
	r, err := unpack(data)
	if err != nil {
		return false, err
	}
	var lines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) == 0 {
		return false, errors.New("bo'sh javob")
	}
	n, err := a.store.AppendList(file, lines)
	if err != nil {
		return false, err
	}
	a.println(fmt.Sprintf("  +%s ta yangi xesh", sigdb.FormatCount(n)))
	return n > 0, nil
}

func (a *app) readWithProgress(r io.Reader, total int64) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, &progressReader{r: r, total: total, quiet: a.quiet})
	if !a.quiet {
		ui.EndStatus()
	}
	return buf.Bytes(), err
}

type progressReader struct {
	r     io.Reader
	n     int64
	total int64
	last  time.Time
	quiet bool
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if !p.quiet && time.Since(p.last) > 200*time.Millisecond {
		p.last = time.Now()
		if p.total > 0 {
			ui.Status(fmt.Sprintf("  %.1f / %.1f MB", float64(p.n)/(1<<20), float64(p.total)/(1<<20)))
		} else {
			ui.Status(fmt.Sprintf("  %.1f MB", float64(p.n)/(1<<20)))
		}
	}
	return n, err
}

// unpack ZIP arxiv bo'lsa ichidagi matn fayllarini, aks holda ma'lumotning o'zini qaytaradi.
func unpack(data []byte) (io.Reader, error) {
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return bytes.NewReader(data), nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var readers []io.Reader
	for _, f := range zr.File {
		n := strings.ToLower(f.Name)
		if f.FileInfo().IsDir() || !(strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".csv")) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		readers = append(readers, bytes.NewReader(b), strings.NewReader("\n"))
	}
	if len(readers) == 0 {
		return nil, errors.New("arxivda .txt fayl yo'q")
	}
	return io.MultiReader(readers...), nil
}

// clamavRemoteVersions DNS TXT yozuvidan main va daily versiyalarini oladi.
func clamavRemoteVersions() map[string]int {
	txts, err := net.LookupTXT(clamavDNS)
	if err != nil || len(txts) == 0 {
		return nil
	}
	f := strings.Split(txts[0], ":")
	if len(f) < 3 {
		return nil
	}
	main, _ := strconv.Atoi(f[1])
	daily, _ := strconv.Atoi(f[2])
	return map[string]int{"main": main, "daily": daily}
}

func localCVDVersion(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	hdr := make([]byte, 512)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return 0
	}
	h, err := sigdb.ReadCVDHeader(hdr)
	if err != nil {
		return 0
	}
	return h.Version
}

// errCDNBlocked ClamAV CDN so'rovni rad etdi (403/429). CDN faqat rasmiy
// yuklovchilarni (freshclam, cvdupdate) o'tkazadi.
var errCDNBlocked = errors.New("ClamAV serveri yuklashni rad etdi")

const clamavHelp = `ClamAV serveri faqat rasmiy yuklovchilarni (freshclam, cvdupdate) o'tkazadi.
  Bazani ulardan biri bilan yuklang — Qalqon uni har yangilanishda avtomatik oladi:
    • cvdupdate (Python kerak):  pip install cvdupdate   va   cvd update
    • yoki ClamAV for Windows (clamav.net/downloads) o'rnatib, freshclam ni ishga tushiring
  Yoki tayyor fayllarni import qiling:  qalqon update --file <papka yoki main.cvd>`

// clamavLocalDirs rasmiy ClamAV vositalari bazani saqlaydigan odatiy papkalar.
func clamavLocalDirs() []string {
	var dirs []string
	if d := os.Getenv("QALQON_CLAMAV_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	homes := map[string]bool{}
	if h, err := os.UserHomeDir(); err == nil {
		homes[h] = true
	}
	usersRoot := "/home"
	if pub := os.Getenv("PUBLIC"); pub != "" {
		usersRoot = filepath.Dir(pub)
	}
	if ents, err := os.ReadDir(usersRoot); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				homes[filepath.Join(usersRoot, e.Name())] = true
			}
		}
	}
	for h := range homes {
		dirs = append(dirs, filepath.Join(h, ".cvdupdate", "database"), filepath.Join(h, ".cvdupdate", "databases"))
	}
	for _, pf := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if pf != "" {
			dirs = append(dirs, filepath.Join(pf, "ClamAV", "database"), filepath.Join(pf, "ClamAV"))
		}
	}
	dirs = append(dirs, `C:\ClamAV\database`, "/var/lib/clamav")
	return dirs
}

// sourceCVDVersion manbalardagi name.cvd yoki name.cld versiyasi.
func (a *app) sourceCVDVersion(name string) int {
	v := localCVDVersion(filepath.Join(a.store.SourcesDir(), name+".cvd"))
	return max(v, localCVDVersion(filepath.Join(a.store.SourcesDir(), name+".cld")))
}

func (a *app) haveClamAV() bool {
	return a.sourceCVDVersion("main") > 0 || a.sourceCVDVersion("daily") > 0
}

// importLocalClamAV freshclam/cvdupdate yuklagan yangiroq bazalarni manbalarga ko'chiradi.
func (a *app) importLocalClamAV(dirs []string) bool {
	changed := false
	for _, name := range []string{"main", "daily"} {
		best, bestV := "", a.sourceCVDVersion(name)
		for _, d := range dirs {
			for _, ext := range []string{".cvd", ".cld"} {
				p := filepath.Join(d, name+ext)
				if v := localCVDVersion(p); v > bestV {
					best, bestV = p, v
				}
			}
		}
		if best == "" {
			continue
		}
		if ch, err := a.importFile(best); err != nil {
			a.println(ui.Yellow(fmt.Sprintf("  ! %s: %v", best, err)))
		} else if ch {
			changed = true
		}
	}
	return changed
}

// updateClamAV ClamAV bazalarini (main, daily) yangilaydi: avval kompyuterdagi
// freshclam/cvdupdate bazalaridan, so'ng (ruxsat bo'lsa) internetdan.
func (a *app) updateClamAV(force bool) (bool, error) {
	changed := a.importLocalClamAV(clamavLocalDirs())
	st := a.state.get()
	if !force && time.Now().Before(st.ClamAVBlockedUntil) {
		if a.haveClamAV() {
			a.println(ui.Dim("ClamAV: server yuklashni rad etgan — kompyuterdagi bazadan foydalanilmoqda."))
			return changed, nil
		}
		return changed, fmt.Errorf("%w (%s gacha qayta urinilmaydi)\n  %s", errCDNBlocked, st.ClamAVBlockedUntil.Format("02.01 15:04"), clamavHelp)
	}
	if !force && time.Since(st.LastClamAVCheck) < clamavMinWait && a.store.CurrentVersion() != "" {
		a.println(ui.Dim("ClamAV: yaqinda tekshirilgan (4 soatda bir martadan ko'p yuklanmaydi)."))
		return changed, nil
	}
	mirror := strings.TrimRight(os.Getenv("QALQON_CLAMAV_MIRROR"), "/")
	if mirror == "" {
		mirror = clamavMirror
	}
	remote := clamavRemoteVersions()
	var firstErr error
	for _, name := range []string{"daily", "main"} {
		localV := a.sourceCVDVersion(name)
		if rv, ok := remote[name]; ok && rv > 0 && localV >= rv {
			a.println(ui.Dim(fmt.Sprintf("ClamAV %s: eng so'nggi (v%d)", name, localV)))
			continue
		}
		dst := filepath.Join(a.store.SourcesDir(), name+".cvd")
		ch, err := a.downloadCVD(mirror+"/"+name+".cvd", dst)
		if errors.Is(err, errCDNBlocked) {
			// Qayta-qayta urinish IP manzilni uzoqroq bloklanishiga olib keladi.
			a.state.set(func(s *appState) {
				s.LastClamAVCheck = time.Now()
				s.ClamAVBlockedUntil = time.Now().Add(24 * time.Hour)
			})
			if a.haveClamAV() {
				a.println(ui.Yellow("ClamAV serveri yuklashni rad etdi — kompyuterdagi bazadan foydalanilmoqda."))
				return changed, nil
			}
			return changed, fmt.Errorf("%w\n  %s", err, clamavHelp)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s.cvd: %w", name, err)
			}
			continue
		}
		if ch {
			_ = os.Remove(filepath.Join(a.store.SourcesDir(), name+".cld"))
			changed = true
		}
	}
	if firstErr == nil {
		a.state.set(func(s *appState) { s.LastClamAVCheck = time.Now() })
	}
	return changed, firstErr
}

// downloadCVD .cvd faylni yuklab oladi va yaxlitligini (MD5) tekshiradi.
func (a *app) downloadCVD(u, dst string) (bool, error) {
	a.println("Yuklanmoqda: " + u)
	req, err := newRequest(u)
	if err != nil {
		return false, err
	}
	if st, err := os.Stat(dst); err == nil {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		a.println(ui.Dim("  o'zgarmagan"))
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return false, fmt.Errorf("%w (%s)", errCDNBlocked, resp.Status)
		}
		return false, fmt.Errorf("server javobi: %s", resp.Status)
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(f, &progressReader{r: resp.Body, total: resp.ContentLength, quiet: a.quiet})
	if !a.quiet {
		ui.EndStatus()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = verifyCVD(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	if lm, perr := http.ParseTime(resp.Header.Get("Last-Modified")); perr == nil {
		_ = os.Chtimes(tmp, lm, lm)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return false, err
	}
	a.println(ui.Green(fmt.Sprintf("  ✔ %s v%d", filepath.Base(dst), localCVDVersion(dst))))
	return true, nil
}

// verifyCVD .cvd sarlavhasi va undagi MD5 nazorat yig'indisini tekshiradi.
func verifyCVD(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := make([]byte, 512)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return errors.New("fayl juda qisqa")
	}
	if _, err := sigdb.ReadCVDHeader(hdr); err != nil {
		return err
	}
	fields := strings.Split(strings.TrimRight(string(hdr), " \x00"), ":")
	if len(fields) > 5 && len(fields[5]) == 32 {
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(fields[5]) {
			return errors.New("MD5 nazorat yig'indisi mos kelmadi (fayl buzilgan)")
		}
	}
	return nil
}

var sigFileExts = map[string]bool{".hdb": true, ".hsb": true, ".mdb": true, ".msb": true, ".ndb": true, ".fp": true, ".sfp": true, ".ign": true, ".ign2": true}

// importFile mahalliy fayldan bazaga import qiladi.
func (a *app) importFile(path string) (bool, error) {
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return a.importDir(path)
	}
	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)
	switch {
	case ext == ".cvd" || ext == ".cld" || ext == ".cud":
		if err := verifyCVD(path); err != nil && ext == ".cvd" {
			return false, err
		}
		name := strings.TrimSuffix(strings.ToLower(base), ext)
		for _, e := range []string{".cvd", ".cld", ".cud"} {
			_ = os.Remove(filepath.Join(a.store.SourcesDir(), name+e))
		}
		if err := copyFile(path, filepath.Join(a.store.SourcesDir(), name+ext)); err != nil {
			return false, err
		}
		a.println(ui.Green(fmt.Sprintf("✔ %s import qilindi (v%d)", base, localCVDVersion(path))))
		return true, nil
	case sigFileExts[ext]:
		if err := copyFile(path, filepath.Join(a.store.SourcesDir(), "user-"+base)); err != nil {
			return false, err
		}
		a.println(ui.Green("✔ " + base + " import qilindi"))
		return true, nil
	default:
		lines := readLines(path)
		n, err := a.store.AppendList("custom.txt", lines)
		if err != nil {
			return false, err
		}
		a.println(ui.Green(fmt.Sprintf("✔ +%d ta xesh qo'shildi (custom.txt)", n)))
		return n > 0, nil
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// importDir papkadagi ClamAV bazalari va imzo fayllarini import qiladi.
func (a *app) importDir(dir string) (bool, error) {
	changed := a.importLocalClamAV([]string{dir})
	ents, err := os.ReadDir(dir)
	if err != nil {
		return changed, err
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || !sigFileExts[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		ch, err := a.importFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return changed, err
		}
		changed = changed || ch
		n++
	}
	if !changed && n == 0 && !a.haveClamAV() {
		return false, errors.New("papkada main.cvd/daily.cvd yoki imzo fayllari topilmadi")
	}
	return changed, nil
}
