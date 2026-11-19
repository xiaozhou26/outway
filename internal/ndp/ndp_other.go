//go:build !linux

package ndp

import "errors"

// Open is only implemented on Linux; proxy NDP is a Linux kernel feature.
func Open(string, int) (*Cache, error) {
	return nil, errors.New("--ndp-proxy is only supported on Linux")
}
