package collector

import (
	"fmt"
	"os"
	"syscall"
)

func directoryIdentity(info os.FileInfo) (string, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), true
	}
	return "", false
}
