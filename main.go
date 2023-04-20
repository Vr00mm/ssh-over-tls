package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var (
	sshServerAddr  = os.Getenv("SSH_SERVER_ADDR")
	httpServerAddr = os.Getenv("HTTP_SERVER_ADDR")
	listenPort     = os.Getenv("LISTEN_PORT")
)

func main() {
	if sshServerAddr == "" || httpServerAddr == "" || listenPort == "" {
		log.Fatal("SSH_SERVER_ADDR, HTTP_SERVER_ADDR, and LISTEN_PORT environment variables are required")
	}

	// Load certificates
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("failed to load certificates: %v", err)
	}

	// Configure TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create a TLS listener on the specified port
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%s", listenPort), config)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	for {
		// Accept incoming connections
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		// Process the connection
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	logger := log.New(os.Stdout, fmt.Sprintf("%s: ", conn.RemoteAddr()), log.LstdFlags)
	clientAddr := conn.RemoteAddr().String()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logger.Printf("failed to cast connection to tls.Conn")
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		logger.Printf("TLS handshake error: %v", err)
		return
	}

	state := tlsConn.ConnectionState()

	// Read the first few bytes to detect the protocol
	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		logger.Printf("failed to read from connection: %v", err)
		return
	}

	// Check if the connection is SSH or HTTP
	protocol := "unknown"
	isSSH := string(buf[:4]) == "SSH-"
	isHTTP := strings.HasPrefix(string(buf), "GET ") || strings.HasPrefix(string(buf), "POST") || strings.HasPrefix(string(buf), "HEAD") || strings.HasPrefix(string(buf), "PUT ") || strings.HasPrefix(string(buf), "DELETE") || strings.HasPrefix(string(buf), "OPTIONS") || strings.HasPrefix(string(buf), "CONNECT")

	var targetAddr string
	if isSSH {
		targetAddr = sshServerAddr
		protocol = "SSH"
	} else if isHTTP {
		targetAddr = httpServerAddr
		protocol = "HTTP"
	} else {
		logger.Printf("unknown protocol")
		return
	}
	logger.Printf("[%s] Protocol=%s Status=OPEN SNI=%s TLSVersion=%x CipherSuite=%x", clientAddr, protocol, state.ServerName, state.Version, state.CipherSuite)
	defer logger.Printf("[%s] Protocol=%s Status=CLOSE SNI=%s TLSVersion=%x CipherSuite=%x", clientAddr, protocol, state.ServerName, state.Version, state.CipherSuite)

	// Forward the connection to the appropriate server
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logger.Printf("failed to dial target server: %v", err)
		return
	}
	defer target.Close()

	// Write the initial bytes to the target server
	if _, err := target.Write(buf); err != nil {
		logger.Printf("failed to write to target server: %v", err)
		return
	}

	// Forward data between the two connections
	done := make(chan struct{})
	go func() {
		io.Copy(target, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, target)
		done <- struct{}{}
	}()
	<-done
}
