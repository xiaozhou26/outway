//go:build !linux

package serverbase

import (
	"io"
	"net"
	"sync"
)

const userspaceCopyBufferSize = 24 * 1024

var userspaceCopyBufferPool = sync.Pool{
	New: func() any { return make([]byte, userspaceCopyBufferSize) },
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func copyStream(dst, src net.Conn) (int64, error) {
	buffer := userspaceCopyBufferPool.Get().([]byte)
	defer userspaceCopyBufferPool.Put(buffer)
	// Hide TCPConn's generic ReaderFrom/WriterTo implementations so CopyBuffer
	// uses the bounded pooled buffer instead of allocating 32 KiB per direction.
	return io.CopyBuffer(writerOnly{dst}, readerOnly{src}, buffer)
}
