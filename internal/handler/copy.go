package handler

import (
	"io"
	"net"
	"sync"
	"time"
)

const (
	// copyBufSize matches io.Copy's internal default to avoid under-utilising buffers.
	copyBufSize = 32 * 1024
	// defaultIdleTimeout is the maximum time to wait for data before closing idle connections.
	defaultIdleTimeout = 5 * time.Minute
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

// BidirectionalCopy performs bidirectional copying between client and backend
// with support for TCP half-close and idle timeout.
// It writes the initial protocol header to the backend, then pipes data in both
// directions. When one direction finishes, it performs a half-close on the destination
// connection to signal end-of-stream while still allowing the reverse direction to complete.
func BidirectionalCopy(client, backend net.Conn, header []byte, idleTimeout time.Duration) error {
	if _, err := backend.Write(header); err != nil {
		return err
	}

	// Use default timeout if not provided.
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}

	// Wait for both directions to complete.
	var wg sync.WaitGroup
	wg.Add(2)

	buf1 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte
	buf2 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte

	// Client -> Backend
	go func() {
		defer wg.Done()
		defer copyBufPool.Put(buf1)

		_ = copyWithIdleTimeout(backend, client, *buf1, idleTimeout)

		// Signal backend that client has finished writing (TCP half-close).
		if tcpConn, ok := backend.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		defer copyBufPool.Put(buf2)

		_ = copyWithIdleTimeout(client, backend, *buf2, idleTimeout)

		// Signal client that backend has finished writing (TCP half-close).
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Wait for both directions to complete.
	wg.Wait()

	return nil
}

// copyWithIdleTimeout copies data from src to dst with an idle timeout.
// The connection deadline is updated before each read to prevent idle connections
// from holding resources indefinitely.
func copyWithIdleTimeout(dst io.Writer, src io.Reader, buf []byte, timeout time.Duration) error {
	conn, ok := src.(net.Conn)
	if !ok {
		// Fallback to regular copy if source is not a net.Conn.
		_, err := io.CopyBuffer(dst, src, buf)
		return err
	}

	for {
		// Set read deadline to detect idle connections.
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
