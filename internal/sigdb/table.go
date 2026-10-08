package sigdb

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// AnySize — hajmi muhim bo'lmagan imzo ("*").
const AnySize = 0xFFFFFFFF

// table — tartiblangan yozuvlar: xesh | hajm (uint32 LE) | nom indeksi (uint32 LE).
type table struct {
	hashLen int
	data    []byte
}

func (t *table) recLen() int { return t.hashLen + 8 }

func (t *table) count() int {
	if t == nil {
		return 0
	}
	return len(t.data) / t.recLen()
}

// lookup xesh va hajm bo'yicha nom indeksini qidiradi.
func (t *table) lookup(h []byte, size uint32) (uint32, bool) {
	if t == nil || len(h) != t.hashLen {
		return 0, false
	}
	rl := t.recLen()
	n := t.count()
	i := sort.Search(n, func(i int) bool { return bytes.Compare(t.data[i*rl:i*rl+t.hashLen], h) >= 0 })
	for ; i < n; i++ {
		rec := t.data[i*rl : (i+1)*rl]
		if !bytes.Equal(rec[:t.hashLen], h) {
			break
		}
		s := binary.LittleEndian.Uint32(rec[t.hashLen:])
		if s == AnySize || s == size {
			return binary.LittleEndian.Uint32(rec[t.hashLen+4:]), true
		}
	}
	return 0, false
}

// tableBuilder yozuvlarni yig'adi va tartiblab yozadi.
type tableBuilder struct {
	hashLen int
	buf     []byte
}

func (b *tableBuilder) add(h []byte, size, name uint32) {
	b.buf = append(b.buf, h...)
	b.buf = binary.LittleEndian.AppendUint32(b.buf, size)
	b.buf = binary.LittleEndian.AppendUint32(b.buf, name)
}

func (b *tableBuilder) count() int { return len(b.buf) / (b.hashLen + 8) }

// sorted tartiblangan va takrorlanmaydigan yozuvlarni qaytaradi.
func (b *tableBuilder) sorted() []byte {
	rl := b.hashLen + 8
	n := b.count()
	idx := make([]uint32, n)
	for i := range idx {
		idx[i] = uint32(i)
	}
	key := func(i uint32) []byte { return b.buf[int(i)*rl : int(i)*rl+b.hashLen+4] }
	sort.Slice(idx, func(x, y int) bool { return bytes.Compare(key(idx[x]), key(idx[y])) < 0 })
	out := make([]byte, 0, len(b.buf))
	var prev []byte
	for _, i := range idx {
		k := key(i)
		if prev != nil && bytes.Equal(prev, k) {
			continue
		}
		prev = k
		out = append(out, b.buf[int(i)*rl:int(i+1)*rl]...)
	}
	return out
}
