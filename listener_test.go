package proxyv2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type testCounters struct {
	read, write uint64
}

func TestListener(t *testing.T) {

	tcpServerTests := []struct {
		name        string
		snet, saddr string // server endpoint
		data        []byte
		raddr       string
		readCount   uint64
	}{
		{"ipv4header", "tcp", ":0", []byte{33, 17, 0, 12, 172, 18, 0, 4, 172, 18, 0, 3, 223, 64, 35, 40}, "172.18.0.4:57152", 28},
		{"ipv4headerAWS", "tcp", ":0", []byte{33, 17, 0, 84, 200, 101, 27, 101, 10, 123, 6, 248, 224, 24, 41, 18, 3, 0, 4, 250, 49, 31, 218, 4, 0, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "200.101.27.101:57368", 100},
		{"ipv4headerAWSHealth", "tcp", ":0", []byte{32, 17, 0, 84, 3, 0, 4, 188, 229, 149, 31, 4, 0, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "3.0.4.188:74", 100},
	}

	for _, tt := range tcpServerTests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen(tt.snet, tt.saddr)
			require.NoError(t, err)

			go connectAndSend(t, ln.Addr(), tt.data)

			counters := &testCounters{}

			pln, err := NewListener(ln, &Config{
				Trace: createTraceFunc(counters),
			})
			require.NoError(t, err)

			c2, err := pln.Accept()
			require.NoError(t, err)

			// read some data from the connection to verify it is functioning
			buf := make([]byte, 4)
			n, err := c2.Read(buf)
			require.NoError(t, err)
			require.Equal(t, n, 4)

			// verify the remote address was changed by the proxy header
			require.Equal(t, tt.raddr, c2.RemoteAddr().String())

			// close the socket to trigger the trace callback
			c2.Close()

			// verify the read count is correct
			require.Equal(t, tt.readCount, counters.read)
		})
	}
}

func connectAndSend(t *testing.T, addr net.Addr, header []byte) {
	// open connection to address
	conn, err := net.Dial(addr.Network(), addr.String())
	require.NoError(t, err)
	conn.Write(signature)
	conn.Write(header)
	conn.Write([]byte{1, 2, 3, 4})
	conn.Close()
}

func createTraceFunc(c *testCounters) func(ps *ProxyConn) {
	return func(ps *ProxyConn) {
		// fmt.Println("readCounter", ps.readCounter)
		// fmt.Println("writeCounter", ps.writeCounter)
		c.read = ps.readCounter
		c.write = ps.writeCounter
	}
}
