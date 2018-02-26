package proxyv2

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

// func ServeTLS(l net.Listener, handler Handler, certFile, keyFile string) error {

// Listener wrapper for the TCP Listener which adds Proxy V2 Support
type Listener struct {
	net.Listener
	config *Config
}

// Config configuration for the proxy listener
type Config struct {
	// Trace is invoked for each new connection and passed the parsed proxy header
	Trace            func(*ProxyConn)
	ProxyHeaderError func(error)
}

// NewListener wraps the supplied listener to provide proxy v2 connections
func NewListener(inner net.Listener, config *Config) (net.Listener, error) {
	if config == nil {
		config = new(Config)
	}
	if config.ProxyHeaderError == nil {
		config.ProxyHeaderError = func(error) {}
	}
	return &Listener{Listener: inner, config: config}, nil
}

// Accept waits for and returns the next connection to the listener.
func (ln Listener) Accept() (net.Conn, error) {

	conn, err := ln.Listener.Accept()
	if err != nil {
		if err == errSignatureNotMatched {
			fmt.Println("Missing proxy v2 header preamble")
		}
		return nil, err
	}

	return &ProxyConn{Conn: conn, config: ln.config}, err
}

// ProxyConn proxy V2 wrapper for a network connection
type ProxyConn struct {
	net.Conn
	config    *Config
	once      sync.Once
	proxyInfo *ProxyV2Info
	srcAddr   net.Addr

	readCounter  uint64
	writeCounter uint64
}

// RemoteAddr returns the remote network address.
func (p *ProxyConn) RemoteAddr() net.Addr {
	p.once.Do(p.readProxyV2)
	if p.srcAddr != nil {
		return p.srcAddr
	}
	return p.Conn.RemoteAddr()
}

// Read implements the Conn Read method.
func (p *ProxyConn) Read(b []byte) (n int, err error) {
	p.once.Do(p.readProxyV2)
	n, err = p.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&p.readCounter, uint64(n))
	return n, nil
}

func (p *ProxyConn) Write(b []byte) (n int, err error) {
	n, err = p.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&p.writeCounter, uint64(n))
	return n, nil
}

// Close close the network connection and trigger the trace record for this connection
func (p *ProxyConn) Close() error {
	p.config.Trace(p)
	return p.Conn.Close()
}

func (p *ProxyConn) readProxyV2() {

	signature, err := checkSignature(p.Conn)
	if err != nil {
		p.Close()
		p.config.ProxyHeaderError(errors.Wrap(err, "failed to check signature"))
		return
	}

	atomic.AddUint64(&p.readCounter, uint64(len(signature)))

	state, err := readV2Info(p.Conn)
	if err != nil {
		p.Close()
		p.config.ProxyHeaderError(errors.Wrap(err, "failed to read v2 header"))
		return
	}

	err = state.Parse()
	if err != nil {
		p.Close()
		p.config.ProxyHeaderError(errors.Wrap(err, "failed to parse header"))
		return
	}

	atomic.AddUint64(&p.readCounter, uint64(state.Hdr.Length))

	p.proxyInfo = state

	p.updateSrcAddr()
}

func (p *ProxyConn) updateSrcAddr() {
	addr := p.proxyInfo.V4Addr.SourceAddr
	port := p.proxyInfo.V4Addr.SourcePort
	srcIP := net.IPv4(addr[0], addr[1], addr[2], addr[3])
	p.srcAddr = &net.TCPAddr{IP: srcIP, Port: int(port)}
}
