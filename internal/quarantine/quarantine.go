// Package quarantine zararli fayllarni xavfsiz saqlaydi: fayl XOR bilan
// kodlanadi (ishga tushib ketmasligi uchun) va asl joyidan o'chiriladi.
package quarantine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const xorKey = 0xA5

// Item — karantindagi fayl haqida ma'lumot.
type Item struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	Threat       string    `json:"threat"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	Date         time.Time `json:"date"`
}

// Store — karantin papkasi.
type Store struct{ Dir string }

// Open karantin papkasini ochadi (kerak bo'lsa yaratadi).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func xor(b []byte) {
	for i := range b {
		b[i] ^= xorKey
	}
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Add faylni karantinga ko'chiradi va asl faylni o'chiradi.
func (s *Store) Add(path, threat string) (Item, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Item{}, err
	}
	sum := sha256.Sum256(data)
	it := Item{ID: newID(), OriginalPath: path, Threat: threat, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Date: time.Now()}
	xor(data)
	bin := filepath.Join(s.Dir, it.ID+".bin")
	if err := os.WriteFile(bin, data, 0o600); err != nil {
		return Item{}, err
	}
	meta, _ := json.MarshalIndent(it, "", "  ")
	if err := os.WriteFile(filepath.Join(s.Dir, it.ID+".json"), meta, 0o600); err != nil {
		os.Remove(bin)
		return Item{}, err
	}
	if err := ForceRemove(path); err != nil {
		// Asl faylni o'chirib bo'lmadi — karantin nusxasini ham bekor qilamiz.
		os.Remove(bin)
		os.Remove(filepath.Join(s.Dir, it.ID+".json"))
		return Item{}, fmt.Errorf("faylni o'chirib bo'lmadi (ehtimol ishlatilmoqda): %w", err)
	}
	return it, nil
}

// ForceRemove faylni "faqat o'qish" atributini olib tashlab o'chiradi.
func ForceRemove(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	_ = os.Chmod(path, 0o666)
	return os.Remove(path)
}

// List karantindagi fayllarni sanasi bo'yicha qaytaradi.
func (s *Store) List() ([]Item, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue
		}
		var it Item
		if json.Unmarshal(b, &it) == nil && it.ID != "" {
			items = append(items, it)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Date.Before(items[j].Date) })
	return items, nil
}

// Find ID yoki ro'yxatdagi tartib raqami (1 dan) bo'yicha elementni topadi.
func (s *Store) Find(ref string) (Item, error) {
	items, err := s.List()
	if err != nil {
		return Item{}, err
	}
	var n int
	if _, err := fmt.Sscanf(ref, "%d", &n); err == nil && fmt.Sprint(n) == ref {
		if n >= 1 && n <= len(items) {
			return items[n-1], nil
		}
	}
	for _, it := range items {
		if it.ID == ref {
			return it, nil
		}
	}
	return Item{}, errors.New("karantinda bunday element topilmadi: " + ref)
}

// Restore faylni asl joyiga (yoki to bo'sh bo'lmasa — to ga) qaytaradi.
func (s *Store) Restore(id, to string) (string, error) {
	it, err := s.Find(id)
	if err != nil {
		return "", err
	}
	dst := it.OriginalPath
	if to != "" {
		dst = to
	}
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("%s allaqachon mavjud", dst)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, it.ID+".bin"))
	if err != nil {
		return "", err
	}
	xor(data)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", err
	}
	return dst, s.remove(it.ID)
}

// Delete elementni karantindan butunlay o'chiradi.
func (s *Store) Delete(id string) error {
	it, err := s.Find(id)
	if err != nil {
		return err
	}
	return s.remove(it.ID)
}

// Clear butun karantinni tozalaydi.
func (s *Store) Clear() (int, error) {
	items, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, it := range items {
		if err := s.remove(it.ID); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

func (s *Store) remove(id string) error {
	if err := os.Remove(filepath.Join(s.Dir, id+".bin")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(filepath.Join(s.Dir, id+".json"))
}
