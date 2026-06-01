package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1 & 2. Read client greeting and negotiate/perform authentication
	if err := negotiateAuth(conn); err != nil {
		log.Printf("Authentication/Negotiation failed: %v", err)
		return
	}

	// 3, 4, 5 & 6. Read CONNECT request, dial target, reply, and relay
	if err := handleConnect(conn); err != nil {
		log.Printf("Connection handling failed: %v", err)
		return
	}
}

func negotiateAuth(conn net.Conn) error {
	// Read Greeting: VER | NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x05 {
		return errors.New("unsupported SOCKS version")
	}

	// Read METHODS
	nmethods := header[1]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	reqUser := os.Getenv("PROXY_USER")
	reqPass := os.Getenv("PROXY_PASS")
	requiresAuth := reqUser != "" || reqPass != ""

	var chosenMethod byte = 0xFF

	foundNoAuth := false
	foundUserPass := false

	for _, m := range methods {
		switch m {
		case 0x00:
			foundNoAuth = true
		case 0x02:
			foundUserPass = true
		}
	}

	if requiresAuth {
		if foundUserPass {
			chosenMethod = 0x02
		}
	} else {
		if foundNoAuth {
			chosenMethod = 0x00
		}
	}

	if _, err := conn.Write([]byte{0x05, chosenMethod}); err != nil {
		return err
	}

	if chosenMethod == 0xFF {
		return errors.New("no acceptable authentication methods")
	}

	if chosenMethod == 0x02 {
		return authenticateUserPass(conn, reqUser, reqPass)
	}

	return nil
}
func authenticateUserPass(conn net.Conn, reqUser, reqPass string) error {
	// Read Auth Request Header: VER (Must be 0x01) | ULEN
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return errors.New("unsupported auth version (expected 0x01)")
	}

	// Read Username
	ulen := header[1]
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	// Read Password Length (PLEN)
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}

	// Read Password
	plen := plenBuf[0]
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	// Validate credentials
	if string(uname) == reqUser && string(passwd) == reqPass {
		conn.Write([]byte{0x01, 0x00}) // Success STATUS = 0x00
		return nil
	}

	conn.Write([]byte{0x01, 0x01}) // Failure STATUS != 0x00
	return errors.New("invalid credentials")
}

func handleConnect(conn net.Conn) error {
	// Read CONNECT Request: VER | CMD | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		sendReply(conn, 0x01)
		return errors.New("unsupported SOCKS version")
	}

	if header[1] != 0x01 {
		sendReply(conn, 0x07)
		return errors.New("unsupported command")
	}

	if header[2] != 0x00 {
		sendReply(conn, 0x01)
		return errors.New("invalid reserved field")
	}
	atyp := header[3]
	var host string

	// Extract target address based on Address Type (ATYP)
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain Name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return err
		}
		host = string(domain)
	default:
		sendReply(conn, 0x08) // Address type not supported
		return errors.New("unsupported address type")
	}

	// Read Port (2 bytes, Big-Endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Dial the target
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		var rep byte = 0x01

		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				rep = 0x04
			} else {
				rep = 0x05
			}
		}

		sendReply(conn, rep)
		return err
	}
	defer target.Close()

	// Send Success Reply
	if err := sendReply(conn, 0x00); err != nil {
		return err
	}

	// Begin bidirectional relay
	return relay(conn, target)
}

func sendReply(conn net.Conn, rep byte) error {
	// SOCKS5 Reply: VER | REP | RSV | ATYP | BND.ADDR (4 bytes for IPv4) | BND.PORT (2 bytes)
	// For standard connect commands, sending all zeroes for the bind address/port is perfectly acceptable.
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func relay(client, target net.Conn) error {
	errc := make(chan error, 2)

	// Helper function to handle a single direction of the relay
	copyData := func(dst net.Conn, src net.Conn) {
		_, err := io.Copy(dst, src)
		// Crucial: Type assert to *net.TCPConn to send a TCP FIN packet (CloseWrite).
		// This tells the other end we are done transmitting, preventing HTTP hanging.
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errc <- err
	}

	// Spawn two goroutines for bidirectional copying
	go copyData(client, target)
	go copyData(target, client)

	// Wait for both streams to finish copying
	err1 := <-errc
	err2 := <-errc

	if err1 != nil {
		return err1
	}
	return err2
}
