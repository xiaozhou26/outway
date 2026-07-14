//go:build !linux

package socks

import "errors"

// udpReactor is unavailable off Linux; callers fall back to the
// goroutine-per-socket model.
type udpReactor struct{}

func newUDPReactor(int) (*udpReactor, error) {
	return nil, errors.New("udp reactor requires Linux epoll")
}

func (r *udpReactor) register(int, func()) error { return errors.New("unsupported") }
func (r *udpReactor) rearm(int) error            { return errors.New("unsupported") }
func (r *udpReactor) deregister(int)             {}
func (r *udpReactor) close()                     {}
