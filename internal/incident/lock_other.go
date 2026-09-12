//go:build !linux && !darwin

package incident

import (
	"errors"
	"os"
)

func acquireLock(path string) (*os.File, error) {
	return nil, errors.New("recording is supported on Linux; offline reports are available on this platform")
}
