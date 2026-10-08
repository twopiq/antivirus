package sigdb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// CVDHeader ClamAV .cvd/.cld fayli sarlavhasi.
type CVDHeader struct {
	Name    string
	Version int
	Sigs    int
	Built   string
}

// ReadCVDHeader faylning 512 baytlik sarlavhasini o'qiydi.
func ReadCVDHeader(hdr []byte) (CVDHeader, error) {
	s := strings.TrimRight(string(hdr), " \x00")
	if !strings.HasPrefix(s, "ClamAV-VDB:") {
		return CVDHeader{}, errors.New("ClamAV bazasi emas")
	}
	f := strings.Split(s, ":")
	var h CVDHeader
	if len(f) > 1 {
		h.Built = f[1]
	}
	if len(f) > 2 {
		h.Version, _ = strconv.Atoi(f[2])
	}
	if len(f) > 3 {
		h.Sigs, _ = strconv.Atoi(f[3])
	}
	return h, nil
}

// walkCVD .cvd/.cld arxividagi har bir faylga fn ni chaqiradi.
func walkCVD(r io.Reader, fn func(name string, r io.Reader) error) (CVDHeader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	hdr := make([]byte, 512)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return CVDHeader{}, err
	}
	h, err := ReadCVDHeader(hdr)
	if err != nil {
		return h, err
	}
	var tr *tar.Reader
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return h, err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(br)
	}
	for {
		th, err := tr.Next()
		if err == io.EOF {
			return h, nil
		}
		if err != nil {
			return h, fmt.Errorf("arxiv buzilgan: %w", err)
		}
		if th.Typeflag != tar.TypeReg && th.Typeflag != tar.TypeRegA {
			continue
		}
		if err := fn(path.Base(th.Name), tr); err != nil {
			return h, err
		}
	}
}

var familyRe = regexp.MustCompile(`^(.+?)-\d+-\d+$`)

// family ClamAV nomidan raqamli qo'shimchani olib tashlaydi:
// "Win.Trojan.Agent-6340983-0" -> "Win.Trojan.Agent".
func family(name string) string {
	if m := familyRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

func decodeHash(s string) ([]byte, bool) {
	switch len(s) {
	case 32, 40, 64:
	default:
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// hashLine "Xesh:Hajm:Nomi" (hdb/hsb) yoki "Hajm:Xesh:Nomi" (mdb/msb) satrini tahlil qiladi.
func hashLine(line string, sizeFirst bool) (h []byte, size uint32, name string, ok bool) {
	f := strings.Split(strings.TrimSpace(line), ":")
	if len(f) < 3 {
		return nil, 0, "", false
	}
	hs, ss := f[0], f[1]
	if sizeFirst {
		hs, ss = f[1], f[0]
	}
	h, ok = decodeHash(strings.ToLower(hs))
	if !ok {
		return nil, 0, "", false
	}
	if ss == "*" {
		size = AnySize
	} else {
		n, err := strconv.ParseUint(ss, 10, 32)
		if err != nil {
			return nil, 0, "", false
		}
		size = uint32(n)
	}
	return h, size, f[2], true
}

// ParseListLine oddiy xeshlar ro'yxati satrini tahlil qiladi: "xesh [nomi]",
// MalwareBazaar CSV satrlari ham qabul qilinadi (md5, sha1 yoki sha256).
func ParseListLine(line string) (h []byte, name string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return nil, "", false
	}
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '"'
	})
	for i, f := range fields {
		if len(f) != 64 && !(i == 0 && (len(f) == 32 || len(f) == 40)) {
			continue
		}
		if b, ok := decodeHash(strings.ToLower(f)); ok {
			if i == 0 && len(fields) > 1 {
				name = strings.Join(fields[1:], " ")
			}
			return b, name, true
		}
	}
	return nil, "", false
}

// isEmptyLine bo'sh yoki izoh satri.
func isEmptyLine(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) == 0 || b[0] == '#'
}
