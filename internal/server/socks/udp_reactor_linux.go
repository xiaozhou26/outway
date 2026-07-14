//go:build linux

package socks

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// udpReactor multiplexes read-readiness of many UDP sockets over a small pool of
// worker goroutines using epoll, so associations no longer each need a blocking
// read goroutine parked in the Go netpoller. Sockets are registered by raw file
// descriptor (obtained via SyscallConn) with EPOLLONESHOT, so at most one worker
// runs a given fd's handler at a time; the handler drains the socket and re-arms
// the fd. This is the piece that lets N associations share M ≪ N goroutines.
type udpReactor struct {
	epfd    int
	eventfd int
	mu      sync.RWMutex
	regs    map[int32]*reactorReg
	wg      sync.WaitGroup
	closed  atomic.Bool
}

// reactorReg couples an fd's ready handler with a lock that serializes it
// against deregistration, so a socket is never closed while its handler runs.
type reactorReg struct {
	handler func()
	mu      sync.Mutex
	dead    bool
}

// newUDPReactor creates a reactor with the given number of worker goroutines and
// starts them. Returns an error if the epoll or eventfd resources cannot be set
// up (callers then fall back to the goroutine-per-socket model).
func newUDPReactor(workers int) (*udpReactor, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	eventfd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(epfd)
		return nil, err
	}
	// The eventfd is level-triggered (no ONESHOT) so a single write wakes every
	// worker for shutdown.
	wake := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(eventfd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, eventfd, &wake); err != nil {
		_ = unix.Close(eventfd)
		_ = unix.Close(epfd)
		return nil, err
	}
	if workers < 1 {
		workers = 1
	}
	r := &udpReactor{epfd: epfd, eventfd: eventfd, regs: make(map[int32]*reactorReg)}
	for range workers {
		r.wg.Add(1)
		go r.loop()
	}
	return r, nil
}

// register adds fd with its ready handler, armed one-shot. The handler is called
// on a worker goroutine when fd becomes readable; it must drain the socket and
// call rearm(fd) to receive further readiness notifications.
func (r *udpReactor) register(fd int, handler func()) error {
	reg := &reactorReg{handler: handler}
	r.mu.Lock()
	r.regs[int32(fd)] = reg
	r.mu.Unlock()
	event := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLONESHOT, Fd: int32(fd)}
	if err := unix.EpollCtl(r.epfd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		r.mu.Lock()
		delete(r.regs, int32(fd))
		r.mu.Unlock()
		return err
	}
	return nil
}

// rearm re-arms a one-shot fd after its handler has drained the socket.
func (r *udpReactor) rearm(fd int) error {
	event := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLONESHOT, Fd: int32(fd)}
	return unix.EpollCtl(r.epfd, unix.EPOLL_CTL_MOD, fd, &event)
}

// deregister removes fd from the reactor and blocks until any in-flight handler
// for it has returned, so the caller can then safely close the underlying
// socket without an fd-reuse hazard.
func (r *udpReactor) deregister(fd int) {
	r.mu.Lock()
	reg := r.regs[int32(fd)]
	delete(r.regs, int32(fd))
	r.mu.Unlock()
	_ = unix.EpollCtl(r.epfd, unix.EPOLL_CTL_DEL, fd, nil)
	if reg != nil {
		// Wait for any running handler, then keep it from running again.
		reg.mu.Lock()
		reg.dead = true
		reg.mu.Unlock()
	}
}

func (r *udpReactor) loop() {
	defer r.wg.Done()
	events := make([]unix.EpollEvent, 128)
	for {
		n, err := unix.EpollWait(r.epfd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		for i := range n {
			fd := events[i].Fd
			if fd == int32(r.eventfd) {
				if r.closed.Load() {
					return
				}
				continue
			}
			r.mu.RLock()
			reg := r.regs[fd]
			r.mu.RUnlock()
			if reg == nil {
				continue
			}
			reg.mu.Lock()
			if !reg.dead {
				reg.handler()
			}
			reg.mu.Unlock()
		}
	}
}

// close stops the reactor and waits for its workers to exit.
func (r *udpReactor) close() {
	if r.closed.Swap(true) {
		return
	}
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(r.eventfd, one[:])
	r.wg.Wait()
	_ = unix.Close(r.eventfd)
	_ = unix.Close(r.epfd)
}
