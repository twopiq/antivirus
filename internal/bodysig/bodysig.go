// Package bodysig ClamAV ".ndb" formatidagi tana (body) imzolarini tahlil
// qiladi va fayl mazmunidan qidiradi.
//
// Imzo formati: Nomi:Turi:Siljish:HexImzo[:MinFL[:MaxFL]]
//
// Qo'llab-quvvatlanadigan hex sintaksisi: aniq baytlar, ?? (istalgan bayt),
// a? va ?a (yarim bayt), * (istalgan uzunlik), {n} {-n} {n-} {n-m} va [n-m]
// (oraliqlar), (aa|bbcc) (muqobillar). Siljishlar: *, n, n,m, EOF-n, EP+n, EP-n.
// Boshqa imkoniyatlarga ega imzolar (masalan !(..), (B), S1+n) o'tkazib yuboriladi.
package bodysig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Fayl turlari (ClamAV "TargetType" qiymatlari).
const (
	TargetAny      = 0
	TargetPE       = 1
	TargetOLE2     = 2
	TargetGraphics = 5
	TargetELF      = 6
	TargetPDF      = 10
	TargetJava     = 12
)

var supportedTargets = map[int]bool{TargetAny: true, TargetPE: true, TargetOLE2: true, TargetGraphics: true, TargetPDF: true, TargetJava: true}

const (
	eByte = iota
	eGap
	eAlt
)

type elem struct {
	kind     uint8
	b, mask  byte
	min, max int // eGap: max < 0 — cheksiz
	alts     [][]byte
}

const (
	offAny = iota
	offAbs
	offEOF
	offEP
)

type offset struct {
	kind  int
	n     int
	shift int
}

// Sig — bitta tana imzosi.
type Sig struct {
	Name     string
	Target   int
	off      offset
	elems    []elem
	anchorAt int // aniq baytlar ketma-ketligining boshlanish indeksi (elems ichida)
	anchor   []byte
}

// ErrUnsupported imzoda qo'llab-quvvatlanmaydigan sintaksis bor.
var ErrUnsupported = errors.New("qo'llab-quvvatlanmaydigan imzo")

const minAnchor = 4

// ParseLine ".ndb" satrini tahlil qiladi.
func ParseLine(line string) (*Sig, error) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return nil, ErrUnsupported
	}
	f := strings.Split(line, ":")
	if len(f) < 4 {
		return nil, errors.New("noto'g'ri ndb satri")
	}
	target, err := strconv.Atoi(f[1])
	if err != nil {
		return nil, err
	}
	if !supportedTargets[target] {
		return nil, ErrUnsupported
	}
	off, err := parseOffset(f[2])
	if err != nil {
		return nil, err
	}
	return Compile(f[0], target, off, f[3])
}

func parseOffset(s string) (offset, error) {
	if s == "*" {
		return offset{kind: offAny}, nil
	}
	var o offset
	shift := ""
	if i := strings.IndexByte(s, ','); i >= 0 {
		s, shift = s[:i], s[i+1:]
	}
	if shift != "" {
		n, err := strconv.Atoi(shift)
		if err != nil || n < 0 {
			return o, ErrUnsupported
		}
		o.shift = n
	}
	switch {
	case strings.HasPrefix(s, "EOF-"):
		n, err := strconv.Atoi(s[4:])
		if err != nil {
			return o, ErrUnsupported
		}
		o.kind, o.n = offEOF, n
	case strings.HasPrefix(s, "EP+"), strings.HasPrefix(s, "EP-"):
		n, err := strconv.Atoi(s[3:])
		if err != nil {
			return o, ErrUnsupported
		}
		if s[2] == '-' {
			n = -n
		}
		o.kind, o.n = offEP, n
	default:
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, ErrUnsupported
		}
		o.kind, o.n = offAbs, n
	}
	return o, nil
}

// MustCompile testlar uchun.
func MustCompile(name, hexsig string) *Sig {
	s, err := Compile(name, TargetAny, offset{kind: offAny}, hexsig)
	if err != nil {
		panic(err)
	}
	return s
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parseGap(s string) (min, max int, err error) {
	atoi := func(x string) (int, error) {
		n, err := strconv.Atoi(x)
		if err != nil || n < 0 {
			return 0, ErrUnsupported
		}
		return n, nil
	}
	switch {
	case !strings.Contains(s, "-"):
		n, err := atoi(s)
		return n, n, err
	case strings.HasPrefix(s, "-"):
		n, err := atoi(s[1:])
		return 0, n, err
	case strings.HasSuffix(s, "-"):
		n, err := atoi(s[:len(s)-1])
		return n, -1, err
	default:
		p := strings.SplitN(s, "-", 2)
		a, err := atoi(p[0])
		if err != nil {
			return 0, 0, err
		}
		b, err := atoi(p[1])
		if err != nil || b < a {
			return 0, 0, ErrUnsupported
		}
		return a, b, nil
	}
}

// Compile hex imzoni kompilyatsiya qiladi.
func Compile(name string, target int, off offset, s string) (*Sig, error) {
	sig := &Sig{Name: name, Target: target, off: off}
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case '*':
			sig.elems = append(sig.elems, elem{kind: eGap, min: 0, max: -1})
			i++
		case '{', '[':
			end := byte('}')
			if c == '[' {
				end = ']'
			}
			j := strings.IndexByte(s[i:], end)
			if j < 0 {
				return nil, ErrUnsupported
			}
			min, max, err := parseGap(s[i+1 : i+j])
			if err != nil {
				return nil, err
			}
			sig.elems = append(sig.elems, elem{kind: eGap, min: min, max: max})
			i += j + 1
		case '(':
			j := strings.IndexByte(s[i:], ')')
			if j < 0 {
				return nil, ErrUnsupported
			}
			var alts [][]byte
			for _, a := range strings.Split(s[i+1:i+j], "|") {
				b, err := hex.DecodeString(a)
				if err != nil || len(b) == 0 {
					return nil, ErrUnsupported
				}
				alts = append(alts, b)
			}
			if len(alts) < 2 {
				return nil, ErrUnsupported
			}
			sig.elems = append(sig.elems, elem{kind: eAlt, alts: alts})
			i += j + 1
		default:
			if i+1 >= len(s) {
				return nil, ErrUnsupported
			}
			h, l := s[i], s[i+1]
			hv, hok := hexNibble(h)
			lv, lok := hexNibble(l)
			var e elem
			switch {
			case hok && lok:
				e = elem{kind: eByte, b: hv<<4 | lv, mask: 0xFF}
			case h == '?' && l == '?':
				e = elem{kind: eByte, mask: 0}
			case h == '?' && lok:
				e = elem{kind: eByte, b: lv, mask: 0x0F}
			case hok && l == '?':
				e = elem{kind: eByte, b: hv << 4, mask: 0xF0}
			default:
				return nil, ErrUnsupported
			}
			sig.elems = append(sig.elems, e)
			i += 2
		}
	}
	// Eng uzun aniq baytlar ketma-ketligini "langar" sifatida tanlaymiz.
	bestAt, bestLen := -1, 0
	for i := 0; i < len(sig.elems); {
		if sig.elems[i].kind != eByte || sig.elems[i].mask != 0xFF {
			i++
			continue
		}
		j := i
		for j < len(sig.elems) && sig.elems[j].kind == eByte && sig.elems[j].mask == 0xFF {
			j++
		}
		if j-i > bestLen {
			bestAt, bestLen = i, j-i
		}
		i = j
	}
	if bestLen < minAnchor {
		return nil, ErrUnsupported
	}
	sig.anchorAt = bestAt
	for _, e := range sig.elems[bestAt : bestAt+bestLen] {
		sig.anchor = append(sig.anchor, e.b)
	}
	return sig, nil
}

// FileInfo — fayl haqida imzolarni tekshirish uchun kerakli ma'lumot.
type FileInfo struct {
	Type int // TargetPE, TargetPDF, ... yoki TargetAny
	EP   int // PE kirish nuqtasining fayldagi siljishi, yo'q bo'lsa -1
}

const bloomBits = 1 << 24

// Matcher ko'p sonli imzolarni bitta o'tishda qidiradi.
type Matcher struct {
	sigs  []*Sig
	index map[uint32][]int32
	bloom []uint64
}

// NewMatcher bo'sh qidiruvchi yaratadi.
func NewMatcher() *Matcher {
	return &Matcher{index: map[uint32][]int32{}, bloom: make([]uint64, bloomBits/64)}
}

func bloomHash(k uint32) uint32 { return (k * 2654435761) >> 8 }

// Add imzoni qo'shadi.
func (m *Matcher) Add(s *Sig) {
	k := binary.LittleEndian.Uint32(s.anchor)
	m.index[k] = append(m.index[k], int32(len(m.sigs)))
	h := bloomHash(k)
	m.bloom[h>>6] |= 1 << (h & 63)
	m.sigs = append(m.sigs, s)
}

// Len imzolar soni.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.sigs)
}

// Scan data ichida topilgan imzolar nomlarini qaytaradi.
func (m *Matcher) Scan(data []byte, info FileInfo) []string {
	if m == nil || len(m.sigs) == 0 || len(data) < minAnchor {
		return nil
	}
	var found []string
	var hit map[int32]bool
	for i := 0; i+minAnchor <= len(data); i++ {
		k := binary.LittleEndian.Uint32(data[i:])
		h := bloomHash(k)
		if m.bloom[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		for _, idx := range m.index[k] {
			if hit[idx] {
				continue
			}
			s := m.sigs[idx]
			if s.Target != TargetAny && s.Target != info.Type {
				continue
			}
			if !bytes.HasPrefix(data[i:], s.anchor) || !s.matchAt(data, i, info) {
				continue
			}
			if hit == nil {
				hit = map[int32]bool{}
			}
			hit[idx] = true
			found = append(found, s.Name)
		}
	}
	return found
}

// Match bitta imzoni butun ma'lumotda tekshiradi (testlar va kichik hajmlar uchun).
func (s *Sig) Match(data []byte, info FileInfo) bool {
	for i := 0; i+len(s.anchor) <= len(data); i++ {
		j := bytes.Index(data[i:], s.anchor)
		if j < 0 {
			return false
		}
		i += j
		if s.matchAt(data, i, info) {
			return true
		}
	}
	return false
}

const stepBudget = 200000

func (s *Sig) matchAt(data []byte, pos int, info FileInfo) bool {
	end := s.anchorAt + len(s.anchor)
	budget := stepBudget
	if !matchFwd(s.elems[end:], data, pos+len(s.anchor), &budget) {
		return false
	}
	return matchBack(s.elems[:s.anchorAt], data, pos, &budget, func(start int) bool {
		return s.offsetOK(start, len(data), info)
	})
}

func (s *Sig) offsetOK(start, size int, info FileInfo) bool {
	want := 0
	switch s.off.kind {
	case offAny:
		return true
	case offAbs:
		want = s.off.n
	case offEOF:
		want = size - s.off.n
	case offEP:
		if info.EP < 0 {
			return false
		}
		want = info.EP + s.off.n
	}
	return start >= want && start <= want+s.off.shift
}

func byteOK(e *elem, c byte) bool { return c&e.mask == e.b }

func matchFwd(es []elem, data []byte, pos int, budget *int) bool {
	for len(es) > 0 && es[0].kind == eByte {
		if pos >= len(data) || !byteOK(&es[0], data[pos]) {
			return false
		}
		es, pos = es[1:], pos+1
	}
	if len(es) == 0 {
		return true
	}
	if *budget--; *budget <= 0 {
		return false
	}
	e := &es[0]
	switch e.kind {
	case eAlt:
		for _, a := range e.alts {
			if bytes.HasPrefix(data[pos:], a) && matchFwd(es[1:], data, pos+len(a), budget) {
				return true
			}
		}
	case eGap:
		lo, hi := pos+e.min, len(data)
		if e.max >= 0 && pos+e.max < hi {
			hi = pos + e.max
		}
		// Keyingi element aniq bayt bo'lsa, tez qidiruv.
		if len(es) > 1 && es[1].kind == eByte && es[1].mask == 0xFF {
			for p := lo; p <= hi && p < len(data); {
				j := bytes.IndexByte(data[p:min(hi+1, len(data))], es[1].b)
				if j < 0 {
					return false
				}
				p += j
				if matchFwd(es[1:], data, p, budget) {
					return true
				}
				if *budget <= 0 {
					return false
				}
				p++
			}
			return false
		}
		for p := lo; p <= hi; p++ {
			if matchFwd(es[1:], data, p, budget) {
				return true
			}
			if *budget <= 0 {
				return false
			}
		}
	}
	return false
}

// matchBack es ni oxiridan boshiga qarab, pos (eksklyuziv oxiri) dan orqaga qarab tekshiradi.
func matchBack(es []elem, data []byte, pos int, budget *int, done func(start int) bool) bool {
	for len(es) > 0 && es[len(es)-1].kind == eByte {
		if pos <= 0 || !byteOK(&es[len(es)-1], data[pos-1]) {
			return false
		}
		es, pos = es[:len(es)-1], pos-1
	}
	if len(es) == 0 {
		return done(pos)
	}
	if *budget--; *budget <= 0 {
		return false
	}
	e := &es[len(es)-1]
	rest := es[:len(es)-1]
	switch e.kind {
	case eAlt:
		for _, a := range e.alts {
			if bytes.HasSuffix(data[:pos], a) && matchBack(rest, data, pos-len(a), budget, done) {
				return true
			}
		}
	case eGap:
		lo := 0
		if e.max >= 0 && pos-e.max > 0 {
			lo = pos - e.max
		}
		for p := pos - e.min; p >= lo; p-- {
			if matchBack(rest, data, p, budget, done) {
				return true
			}
			if *budget <= 0 {
				return false
			}
		}
	}
	return false
}
