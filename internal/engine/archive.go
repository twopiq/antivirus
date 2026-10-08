package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

// scanCtx — bitta yuqori darajadagi faylni tekshirish holati (arxivlar uchun cheklovlar).
type scanCtx struct {
	path   string // diskdagi fayl
	depth  int
	budget int64 // arxivlardan ochilishi mumkin bo'lgan qolgan baytlar
}

func isZipData(data []byte) bool { return bytes.HasPrefix(data, []byte("PK\x03\x04")) }

func isGzip(data []byte) bool { return len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b }

func isTar(data []byte) bool { return len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")) }

// readLimited arxiv elementini cheklov bilan o'qiydi.
func (e *Engine) readLimited(r io.Reader, sc *scanCtx) ([]byte, bool) {
	limit := min(e.MaxSize, sc.budget)
	if limit <= 0 {
		return nil, false
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil && len(buf) == 0 {
		return nil, false
	}
	if int64(len(buf)) > limit {
		return nil, false // juda katta yoki "zip bomb"
	}
	sc.budget -= int64(len(buf))
	return buf, true
}

func (e *Engine) scanMember(name string, data []byte, sc *scanCtx) []Threat {
	child := &scanCtx{path: sc.path, depth: sc.depth + 1, budget: sc.budget}
	ts := e.scanData(name, data, child)
	sc.budget = child.budget
	for i := range ts {
		if ts[i].Inner != "" {
			ts[i].Inner = name + " > " + ts[i].Inner
		} else {
			ts[i].Inner = name
		}
	}
	return ts
}

// scanZip ZIP (shu jumladan .docx, .xlsm, .jar) ichidagi fayllarni tekshiradi.
func (e *Engine) scanZip(data []byte, sc *scanCtx) []Threat {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []Threat
	for i, f := range zr.File {
		if i >= e.MaxArchiveEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&0x1 != 0 || int64(f.UncompressedSize64) > e.MaxSize { // shifrlangan yoki juda katta
			for _, t := range checkName(f.Name) {
				t.Inner = f.Name
				out = append(out, t)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf, ok := e.readLimited(rc, sc)
		rc.Close()
		if !ok {
			continue
		}
		for _, t := range checkOOXMLPart(f.Name, buf) {
			t.Inner = f.Name
			out = append(out, t)
		}
		out = append(out, e.scanMember(f.Name, buf, sc)...)
	}
	return out
}

// scanGzip .gz va .tar.gz fayllarni tekshiradi.
func (e *Engine) scanGzip(name string, data []byte, sc *scanCtx) []Threat {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer zr.Close()
	buf, ok := e.readLimited(zr, sc)
	if !ok {
		return nil
	}
	inner := zr.Name
	if inner == "" {
		inner = strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".tgz")
	}
	return e.scanMember(inner, buf, sc)
}

// scanTar tar arxiv ichidagi fayllarni tekshiradi.
func (e *Engine) scanTar(data []byte, sc *scanCtx) []Threat {
	tr := tar.NewReader(bytes.NewReader(data))
	var out []Threat
	for i := 0; i < e.MaxArchiveEntries; i++ {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		buf, ok := e.readLimited(tr, sc)
		if !ok {
			continue
		}
		out = append(out, e.scanMember(h.Name, buf, sc)...)
	}
	return out
}
