//go:build windows

package system

import (
	"context"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Watch papkalardagi yangi va o'zgargan fayllarni ReadDirectoryChangesW orqali
// kuzatadi va har birining yo'lini fn ga beradi. ctx tugaguncha bloklaydi.
func Watch(ctx context.Context, dirs []string, fn func(path string)) {
	var wg sync.WaitGroup
	for _, d := range dirs {
		wg.Add(1)
		go func(dir string) {
			defer wg.Done()
			watchDir(ctx, dir, fn)
		}(d)
	}
	wg.Wait()
}

func watchDir(ctx context.Context, dir string, fn func(string)) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		windows.CancelIoEx(h, nil)
		windows.CloseHandle(h)
	}()
	defer close(stop)

	const mask = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_SIZE | windows.FILE_NOTIFY_CHANGE_CREATION
	buf := make([]byte, 64*1024)
	for ctx.Err() == nil {
		var n uint32
		if err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true, mask, &n, nil, 0); err != nil {
			return
		}
		for off := uint32(0); n > 0 && off+12 <= n; {
			info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buf[off]))
			nameLen := int(info.FileNameLength / 2)
			if int(off)+12+int(info.FileNameLength) > len(buf) {
				break
			}
			name := unsafe.Slice(&info.FileName, nameLen)
			switch info.Action {
			case windows.FILE_ACTION_ADDED, windows.FILE_ACTION_MODIFIED, windows.FILE_ACTION_RENAMED_NEW_NAME:
				fn(filepath.Join(dir, windows.UTF16ToString(name)))
			}
			if info.NextEntryOffset == 0 {
				break
			}
			off += info.NextEntryOffset
		}
	}
}
