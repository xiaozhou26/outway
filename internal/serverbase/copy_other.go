//go:build !linux

package serverbase

import (
	"io"
	"net"
	"sync"
)

const userspaceCopyBufferSize = 24 * 1024

type userspaceCopyBuffer [userspaceCopyBufferSize]byte

var userspaceCopyBufferPool = sync.Pool{
	New: func() any { return new(userspaceCopyBuffer) },
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func copyStream(dst, src net.Conn) (int64, error) {
	buffer := userspaceCopyBufferPool.Get().(*userspaceCopyBuffer)
	defer userspaceCopyBufferPool.Put(buffer)
	// Hide TCPConn's generic ReaderFrom/WriterTo implementations so CopyBuffer
	// uses the bounded pooled buffer instead of allocating 32 KiB per direction.
	return io.CopyBuffer(writerOnly{dst}, readerOnly{src}, buffer[:])
}
