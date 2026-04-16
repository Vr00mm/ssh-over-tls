package handler

import (
	"io"
	"net"
	"sync"
)

const (
	// copyBufSize matches io.Copy's internal default to avoid under-utilising buffers.
	copyBufSize = 32 * 1024
)

// copyBufPool reuses 32 KiB copy buffers across connections.
// Each io.CopyBuffer call otherwise allocates one on the heap; at high
// connection rates this creates significant GC pressure.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// BidirectionalCopy performs bidirectional copying between client and backend.
// It writes the initial protocol header to the backend, then pipes data in both
// directions until either side closes the connection.
func BidirectionalCopy(client, backend net.Conn, header []byte) error {
	if _, err := backend.Write(header); err != nil {
		return err
	}

	// Buffer size 2 prevents goroutine leak: both goroutines can send even if
	// only one is received (we return as soon as either direction closes).
	done := make(chan struct{}, 2)

	buf1 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte
	buf2 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte

	// Client -> Backend
	go func() {
		defer copyBufPool.Put(buf1)

		_, _ = io.CopyBuffer(backend, client, *buf1)

		done <- struct{}{}
	}()

	// Backend -> Client
	go func() {
		defer copyBufPool.Put(buf2)

		_, _ = io.CopyBuffer(client, backend, *buf2)

		done <- struct{}{}
	}()

	<-done

	return nil
}
