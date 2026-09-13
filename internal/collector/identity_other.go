//go:build !linux

package collector

import "os"

// Non-Linux builds support fixture parsing and offline reporting. The production
// agent is Linux-only, where directory identity includes device and inode.
func directoryIdentity(info os.FileInfo) (string, bool) { return "", false }
