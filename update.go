package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/twopiq/antivirus/internal/engine"
	"github.com/twopiq/antivirus/internal/ui"
)

const (
	bazaarRecent = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
	bazaarFull   = "https://bazaar.abuse.ch/export/txt/sha256/full/"
)

// update virus bazasini internetdan yoki mahalliy fayldan yangilaydi.
func (a *app) update(url, file string, full bool) int {
	var r io.Reader
	source := file
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Println(ui.Red("Faylni ochib bo'lmadi: " + err.Error()))
			return 1
		}
		defer f.Close()
		r = f
	} else {
		if url == "" {
			url = bazaarRecent
			if full {
				url = bazaarFull
			}
		}
		source = url
		fmt.Println("Yuklanmoqda: " + url)
		data, err := download(url)
		if err != nil {
			fmt.Println(ui.Red("Yuklab bo'lmadi: " + err.Error()))
			fmt.Println(ui.Dim("Internet aloqasini tekshiring. abuse.ch kalit talab qilsa, uni QALQON_ABUSE_KEY o'zgaruvchisiga yozing."))
			return 1
		}
		r, err = unpack(data)
		if err != nil {
			fmt.Println(ui.Red("Arxivni ochib bo'lmadi: " + err.Error()))
			return 1
		}
	}
	added, total, err := engine.MergeHashFile(a.sigPath, r, "")
	if err != nil {
		fmt.Println(ui.Red("Bazani yozib bo'lmadi: " + err.Error()))
		return 1
	}
	db, err := engine.LoadSignatureDB(a.sigPath)
	if err == nil {
		a.eng.DB = db
	}
	fmt.Println(ui.Green(fmt.Sprintf("✔ Baza yangilandi: +%d ta yangi imzo, jami %d ta (%s)", added, total, source)))
	a.logLine(fmt.Sprintf("BAZA YANGILANDI +%d jami %d %s", added, total, source))
	return 0
}

func download(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Qalqon-Antivirus/"+version)
	if k := os.Getenv("QALQON_ABUSE_KEY"); k != "" {
		req.Header.Set("Auth-Key", k)
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server javobi: %s", resp.Status)
	}
	var buf bytes.Buffer
	pr := &progressReader{r: resp.Body, total: resp.ContentLength}
	_, err = io.Copy(&buf, pr)
	ui.EndStatus()
	return buf.Bytes(), err
}

type progressReader struct {
	r     io.Reader
	n     int64
	total int64
	last  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if time.Since(p.last) > 200*time.Millisecond {
		p.last = time.Now()
		if p.total > 0 {
			ui.Status(fmt.Sprintf("  %.1f / %.1f MB", float64(p.n)/(1<<20), float64(p.total)/(1<<20)))
		} else {
			ui.Status(fmt.Sprintf("  %.1f MB", float64(p.n)/(1<<20)))
		}
	}
	return n, err
}

// unpack ZIP arxiv bo'lsa ichidagi matn faylini, aks holda ma'lumotning o'zini qaytaradi.
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
		if f.FileInfo().IsDir() || !(strings.HasSuffix(strings.ToLower(f.Name), ".txt") || strings.HasSuffix(strings.ToLower(f.Name), ".csv")) {
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
		return nil, fmt.Errorf("arxivda .txt fayl yo'q")
	}
	return io.MultiReader(readers...), nil
}
