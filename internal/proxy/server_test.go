package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCert writes a self-signed ECDSA P-256 certificate and private key
// to temp files and returns their paths.
func generateTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()

	certFile = filepath.Join(dir, "cert.pem")
	if err := writePEM(certFile, "CERTIFICATE", certDER); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyFile = filepath.Join(dir, "key.pem")
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certFile, keyFile
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.Create(path) //nolint:gosec // G304: test helper writes to t.TempDir() paths only
	if err != nil {
		return err
	}

	defer f.Close() //nolint:errcheck // test helper, close error not actionable

	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

// startMockBackend starts a TCP server on a random port that accepts one connection,
// reads all bytes until EOF, and delivers them on the returned channel.
func startMockBackend(t *testing.T) (addr string, received <-chan []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { ln.Close() }) //nolint:errcheck,gosec // test cleanup

	ch := make(chan []byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed at test end
		}

		defer conn.Close() //nolint:errcheck // test mock

		data, _ := io.ReadAll(conn)
		ch <- data
	}()

	return ln.Addr().String(), ch
}

// startServer creates a proxy server, starts serving on a random TLS port, and
// returns the proxy address. The server stops and drains connections when the test ends.
func startServer(t *testing.T, sshAddr, httpAddr string) string {
	t.Helper()

	certFile, keyFile := generateTestCert(t)

	srv, err := New(sshAddr, httpAddr, "0", certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load cert for listener: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		defer close(done)

		srv.serve(ctx, listener) //nolint:errcheck,gosec // errors surfaced via test assertions
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop within 5s")
		}
	})

	return listener.Addr().String()
}

// dialProxy dials the proxy address over TLS, skipping certificate verification
// (the proxy uses a self-signed test certificate).
func dialProxy(t *testing.T, proxyAddr string) *tls.Conn {
	t.Helper()

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: test-only, self-signed cert
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}

	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec // test cleanup

	return conn
}

// --- detectProtocol ---

func TestDetectProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		header       string
		wantProtocol string
		wantOK       bool
	}{
		{name: "SSH", header: "SSH-2.0-", wantProtocol: "SSH", wantOK: true},
		{name: "GET", header: "GET / HT", wantProtocol: "HTTP", wantOK: true},
		{name: "POST", header: "POST / H", wantProtocol: "HTTP", wantOK: true},
		{name: "HEAD", header: "HEAD / H", wantProtocol: "HTTP", wantOK: true},
		{name: "PUT", header: "PUT / HT", wantProtocol: "HTTP", wantOK: true},
		{name: "DELETE", header: "DELETE /", wantProtocol: "HTTP", wantOK: true},
		{name: "OPTIONS", header: "OPTIONS ", wantProtocol: "HTTP", wantOK: true},
		{name: "CONNECT", header: "CONNECT ", wantProtocol: "HTTP", wantOK: true},
		{name: "unknown", header: "UNKNOWN!", wantProtocol: "", wantOK: false},
		{name: "binary", header: "\x00\x01\x02\x03\x04\x05\x06\x07", wantProtocol: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := detectProtocol(tt.header)
			if ok != tt.wantOK {
				t.Errorf("detectProtocol(%q) ok = %v, want %v", tt.header, ok, tt.wantOK)
			}

			if got != tt.wantProtocol {
				t.Errorf("detectProtocol(%q) protocol = %q, want %q", tt.header, got, tt.wantProtocol)
			}
		})
	}
}

// --- New ---

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	certFile, keyFile := generateTestCert(t)

	srv, err := New(
		"localhost:22", "localhost:80", "443", certFile, keyFile,
		WithDialTimeout(30*time.Second),
		WithHandshakeTimeout(15*time.Second),
	)
	if err != nil {
		t.Fatalf("New() with options error = %v", err)
	}

	if srv.dialTimeout != 30*time.Second {
		t.Errorf("dialTimeout = %v, want %v", srv.dialTimeout, 30*time.Second)
	}

	if srv.handshakeTimeout != 15*time.Second {
		t.Errorf("handshakeTimeout = %v, want %v", srv.handshakeTimeout, 15*time.Second)
	}
}

func TestNew_InvalidCert(t *testing.T) {
	t.Parallel()

	_, err := New("localhost:22", "localhost:80", "443", "/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("New() with nonexistent cert files returned nil error")
	}
}

// --- Server integration ---

func TestServer_RoutesTraffic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  []byte
		wantSSH bool
	}{
		{name: "SSH routed to SSH backend", header: []byte("SSH-2.0-"), wantSSH: true},
		{name: "HTTP routed to HTTP backend", header: []byte("GET / HT"), wantSSH: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sshAddr, sshReceived := startMockBackend(t)
			httpAddr, httpReceived := startMockBackend(t)

			proxyAddr := startServer(t, sshAddr, httpAddr)

			conn := dialProxy(t, proxyAddr)

			if _, err := conn.Write(tt.header); err != nil {
				t.Fatalf("write header: %v", err)
			}

			conn.Close() //nolint:errcheck,gosec // close triggers EOF on backend

			var received <-chan []byte
			if tt.wantSSH {
				received = sshReceived
			} else {
				received = httpReceived
			}

			select {
			case data := <-received:
				if !bytes.Equal(data, tt.header) {
					t.Errorf("backend received %q, want %q", data, tt.header)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for backend to receive data")
			}
		})
	}
}

func TestServer_TLSHandshakeFailure(t *testing.T) {
	t.Parallel()

	sshAddr, _ := startMockBackend(t)
	httpAddr, _ := startMockBackend(t)
	proxyAddr := startServer(t, sshAddr, httpAddr)

	// Raw TCP connection — not a valid TLS ClientHello.
	// The proxy's Handshake() call will fail and close the connection.
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}

	defer conn.Close() //nolint:errcheck // test cleanup

	conn.Write([]byte("not a TLS client hello\r\n")) //nolint:errcheck,gosec // G104: test write, error not actionable

	// Drain until the server closes (sends TLS alert then EOF).
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck,gosec // G104: test deadline, error not actionable

	buf := make([]byte, 256)

	for {
		_, readErr := conn.Read(buf)
		if readErr != nil {
			break
		}
	}
}

func TestServer_ReadHeaderFailure(t *testing.T) {
	t.Parallel()

	sshAddr, _ := startMockBackend(t)
	httpAddr, _ := startMockBackend(t)
	proxyAddr := startServer(t, sshAddr, httpAddr)

	// Complete TLS handshake but only send 3 bytes then close.
	// The server's io.ReadFull (needs 8 bytes) fails with io.ErrUnexpectedEOF.
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: test-only self-signed cert

	conn, err := tls.Dial("tcp", proxyAddr, tlsCfg)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}

	conn.Write([]byte("SSH")) //nolint:errcheck,gosec // G104: test write, error not actionable
	conn.Close()              //nolint:errcheck,gosec // G104: test close, triggers server-side EOF

	// Verify the server is still accepting connections after the error.
	_ = dialProxy(t, proxyAddr)
}

func TestServer_BackendDialFailure(t *testing.T) {
	t.Parallel()

	// Grab a random port then release it — nothing will be listening there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	unavailableAddr := ln.Addr().String()
	ln.Close() //nolint:errcheck,gosec // intentionally released so the port is unreachable

	proxyAddr := startServer(t, unavailableAddr, unavailableAddr)

	conn := dialProxy(t, proxyAddr)

	if _, err := conn.Write([]byte("SSH-2.0-")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Proxy fails to dial the backend and closes our connection.
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck,gosec // G104: test deadline, error not actionable

	buf := make([]byte, 1)

	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after backend dial failure")
	}
}

func TestServer_UnknownProtocol_ClosesConnection(t *testing.T) {
	t.Parallel()

	sshAddr, _ := startMockBackend(t)
	httpAddr, _ := startMockBackend(t)

	proxyAddr := startServer(t, sshAddr, httpAddr)

	conn := dialProxy(t, proxyAddr)

	if _, err := conn.Write([]byte("UNKNOWN!")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The proxy closes the connection on unknown protocol; Read must return an error.
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck,gosec // test assertion deadline

	buf := make([]byte, 1)

	_, err := conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed by proxy, got nil error on Read")
	}
}
