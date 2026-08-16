//go:build !windows

package http

import "os"

func replaceFile(source, target string) error {
	return os.Rename(source, target)
}
