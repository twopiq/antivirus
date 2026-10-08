package main

import (
	"encoding/gob"
	"os"
	"strings"
	"sync"
)

// cacheMinSize — faqat shu hajmdan katta fayllar keshlanadi (kichik fayllarni
// qayta tekshirish arzon, kesh esa xotirani band qiladi).
const cacheMinSize = 64 << 10

// scanCache toza deb topilgan fayllarni eslab qoladi: fayl o'zgarmagan va
// baza yangilanmagan bo'lsa, keyingi tekshiruvda qayta o'qilmaydi.
type scanCache struct {
	path    string
	mu      sync.Mutex
	entries map[string]cacheEntry
	dirty   bool
}

type cacheEntry struct {
	Size    int64
	ModTime int64
	Version string
}

func openCache(path string) *scanCache {
	c := &scanCache{path: path, entries: map[string]cacheEntry{}}
	if f, err := os.Open(path); err == nil {
		_ = gob.NewDecoder(f).Decode(&c.entries)
		f.Close()
	}
	return c
}

func (c *scanCache) clean(p string, info os.FileInfo, ver string) bool {
	if info.Size() < cacheMinSize {
		return false
	}
	c.mu.Lock()
	e, ok := c.entries[strings.ToLower(p)]
	c.mu.Unlock()
	return ok && e.Version == ver && e.Size == info.Size() && e.ModTime == info.ModTime().UnixNano()
}

func (c *scanCache) markClean(p string, info os.FileInfo, ver string) {
	if info.Size() < cacheMinSize {
		return
	}
	c.mu.Lock()
	c.entries[strings.ToLower(p)] = cacheEntry{info.Size(), info.ModTime().UnixNano(), ver}
	c.dirty = true
	c.mu.Unlock()
}

func (c *scanCache) save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(c.entries); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	c.dirty = false
	return os.Rename(tmp, c.path)
}

func (c *scanCache) reset() {
	c.mu.Lock()
	c.entries = map[string]cacheEntry{}
	c.dirty = true
	c.mu.Unlock()
}
