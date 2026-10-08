package main

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"
)

// appState — oxirgi tekshiruv va yangilanish vaqtlari.
type appState struct {
	path string
	mu   sync.Mutex

	LastQuick       time.Time `json:"last_quick"`
	LastFull        time.Time `json:"last_full"`
	LastUpdate      time.Time `json:"last_update"`
	LastClamAVCheck time.Time `json:"last_clamav_check"`
	// ClamAVBlockedUntil — ClamAV CDN 403 qaytargandan keyin serverga qayta murojaat qilinmaydigan vaqt.
	ClamAVBlockedUntil time.Time `json:"clamav_blocked_until"`
}

func loadState(path string) *appState {
	s := &appState{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, s)
	}
	return s
}

func (s *appState) set(fn func(*appState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, s) // boshqa jarayon yozgan qiymatlarni saqlab qolish
	}
	fn(s)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(s.path, b, 0o644)
}

func (s *appState) get() appState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, s)
	}
	return appState{LastQuick: s.LastQuick, LastFull: s.LastFull, LastUpdate: s.LastUpdate, LastClamAVCheck: s.LastClamAVCheck, ClamAVBlockedUntil: s.ClamAVBlockedUntil}
}

// ago vaqtni "3 kun oldin" ko'rinishida yozadi.
func ago(t time.Time) string {
	if t.IsZero() {
		return "hech qachon"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "hozirgina"
	case d < time.Hour:
		return fmtInt(int(d.Minutes())) + " daqiqa oldin"
	case d < 24*time.Hour:
		return fmtInt(int(d.Hours())) + " soat oldin"
	}
	return fmtInt(int(d.Hours()/24)) + " kun oldin"
}

func fmtInt(n int) string { return strconv.Itoa(n) }
