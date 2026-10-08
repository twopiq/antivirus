//go:build !windows

package system

import (
	"context"
	"io/fs"
	"path/filepath"
	"time"
)

type stamp struct {
	size int64
	mod  time.Time
}

func snapshot(root string) map[string]stamp {
	out := map[string]stamp{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				out[p] = stamp{info.Size(), info.ModTime()}
			}
		}
		return nil
	})
	return out
}

// Watch papkalarni har 2 soniyada so'rab kuzatadi (Windows bo'lmagan tizimlar uchun).
func Watch(ctx context.Context, dirs []string, fn func(path string)) {
	snaps := map[string]map[string]stamp{}
	for _, d := range dirs {
		snaps[d] = snapshot(d)
	}
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		for _, d := range dirs {
			now := snapshot(d)
			for p, st := range now {
				if old, ok := snaps[d][p]; !ok || old != st {
					fn(p)
				}
			}
			snaps[d] = now
		}
	}
}
