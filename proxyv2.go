package proxyv2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"
)

const (

	// TCPOverIPV4 The forwarded connection uses TCP over the AF_INET
	// protocol family. Address length is 2*4 + 2*2 = 12 bytes.
	TCPOverIPV4 = 0x11

	// TCPOverIPV4AddrSize length of the ipv4 addr in the header
	TCPOverIPV4AddrSize = 12

	// ProxyHeaderSize length of the proxy header
	ProxyHeaderSize = 4

	// TLVHeaderSize length of the TLV header
	TLVHeaderSize = 3

	// MaxProxyHeaderLength used to limit the size of the proxy header
	MaxProxyHeaderLength = 10 * 1024

	// MaxProxyTLVLength used to limit the size of the TLV
	MaxProxyTLVLength = 1 * 1024
)

var (
	// this is returned when the socket doesn't match the signature
	errSignatureNotMatched = errors.New("Proxy V2 Signature not returned from connection")

	signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

// struct proxy_hdr_v2 {
//     uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
//     uint8_t ver_cmd;  /* protocol version and command */
//     uint8_t fam;      /* protocol family and address */
//     uint16_t len;     /* number of following bytes part of the header */
// };

// ProxyHeaderV2 used to decode the proxy version 2 header
type ProxyHeaderV2 struct {
	VerCmd uint8
	Family uint8
	Length uint16
}

// RawBytes return the raw bytes for the proxyheader
func (ph *ProxyHeaderV2) RawBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, ph)
	return buf.Bytes()
}

func (ph *ProxyHeaderV2) String() string {
	return fmt.Sprintf("Header Version: %+v Family: %+v Length: %v", ph.VerCmd, ph.Family, ph.Length)
}

// Parse decode the contents of the proxy header
func (ph *ProxyV2Info) Parse() error {

	buf := bytes.NewBuffer(ph.RawData)

	switch ph.Hdr.Family {
	case TCPOverIPV4:
		addr, err := readV2Addr(buf)
		if err != nil {
			return errors.Wrap(err, "failed to parse TCPOverIPV4")
		}
		ph.V4Addr = addr
	default:
		return errors.Errorf("Unknown Family: ", ph.Hdr.Family)
	}

	remainder := int(ph.Hdr.Length - TCPOverIPV4AddrSize)

	tlvs, tlvTotal, err := readTLVs(buf, remainder)
	if err != nil {
		return errors.Wrap(err, "failed to parse TLVs")
	}

	if remainder-tlvTotal < 0 {
		return errors.Errorf("Data parse failed result left over: ", remainder-tlvTotal)
	}

	ph.TLVs = tlvs

	return nil
}

// ProxyAddressV4 for TCP/UDP over IPv4, len = 12
type ProxyAddressV4 struct {
	SourceAddr [4]byte
	DestAddr   [4]byte
	SourcePort uint16
	DestPort   uint16
}

// SourceIP return the source IPV4 address
func (pa *ProxyAddressV4) SourceIP() net.IP {
	return net.IPv4(pa.SourceAddr[0], pa.SourceAddr[1], pa.SourceAddr[2], pa.SourceAddr[3])
}

// DestIP return the destination IPV4 address
func (pa *ProxyAddressV4) DestIP() net.IP {
	return net.IPv4(pa.DestAddr[0], pa.DestAddr[1], pa.DestAddr[2], pa.DestAddr[3])
}

func (pa *ProxyAddressV4) String() string {
	return fmt.Sprintf("AddressV4 %s:%d -> %s:%d", pa.SourceIP(), pa.SourcePort, pa.DestIP(), pa.DestPort)
}

// ProxyTLVHeader proxy v2 TLV header data
type ProxyTLVHeader struct {
	Type   uint8
	Length uint16
}

func (pt *ProxyTLVHeader) String() string {
	return fmt.Sprintf("TLVHeader Type: %+v Length: %x", pt.Type, pt.Length)
}

// ProxyTLV proxy v2 TLV
type ProxyTLV struct {
	Hdr  *ProxyTLVHeader
	Data []byte
}

func (pt *ProxyTLV) String() string {
	return fmt.Sprintf("TLV Hdr: %+v Data: %x", pt.Hdr, pt.Data)
}

// ProxyV2Info info from the proxy v2 header
type ProxyV2Info struct {
	Hdr     *ProxyHeaderV2
	V4Addr  *ProxyAddressV4
	TLVs    []*ProxyTLV
	RawData []byte
}

// ReadV2State read the proxy v2 state
func readV2Info(rd io.Reader) (*ProxyV2Info, error) {

	readHdr := new(ProxyHeaderV2)

	err := binary.Read(rd, binary.BigEndian, readHdr)
	if err != nil {
		return nil, err
	}

	proxyHeaderLen := int(readHdr.Length)

	// sanity check the length
	if proxyHeaderLen < 0 || proxyHeaderLen > MaxProxyHeaderLength {
		return nil, errors.Errorf("bad header length supplied: %n", proxyHeaderLen)
	}

	state := new(ProxyV2Info)

	state.Hdr = readHdr
	state.RawData = make([]byte, proxyHeaderLen)

	_, err = io.ReadFull(rd, state.RawData)
	if err != nil {
		return nil, err
	}

	return state, nil
}

// CheckSignature check the signature
func checkSignature(rd io.Reader) ([]byte, error) {
	readSig := make([]byte, 12)

	_, err := io.ReadFull(rd, readSig)
	if err != nil {
		return nil, err
	}

	for n, bt := range readSig {
		if bt != signature[n] {
			return nil, errSignatureNotMatched
		}
	}

	return readSig, nil
}

func readV2Addr(rd io.Reader) (*ProxyAddressV4, error) {

	readAddr := new(ProxyAddressV4)

	err := binary.Read(rd, binary.BigEndian, readAddr)
	if err != nil {
		return nil, err
	}

	return readAddr, nil
}

func readTLVData(rd io.Reader, length int) ([]byte, error) {

	// sanity check the length
	if length < 0 || length > MaxProxyTLVLength {
		return nil, errors.Errorf("bad TLV length supplied: %n", length)
	}

	tlvData := make([]byte, length)

	_, err := io.ReadFull(rd, tlvData)
	if err != nil {
		return nil, err
	}

	return tlvData, nil
}

func readTLV(rd io.Reader) (*ProxyTLV, int, error) {

	tlvHdr := new(ProxyTLVHeader)

	err := binary.Read(rd, binary.BigEndian, tlvHdr)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to read tlv header")
	}

	data, err := readTLVData(rd, int(tlvHdr.Length))
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to read tlv data")
	}

	return &ProxyTLV{Hdr: tlvHdr, Data: data}, int(TLVHeaderSize + tlvHdr.Length), nil
}

func readTLVs(rd io.Reader, remainder int) ([]*ProxyTLV, int, error) {
	tlvs := []*ProxyTLV{}
	tlvTotal := 0

	for {
		if remainder <= 0 {
			break
		}
		tlv, tlvLen, err := readTLV(rd)
		if err != nil {
			return nil, 0, errors.Wrap(err, "failed to read TLV")
		}

		if tlv.Hdr.Type == 0 && tlv.Hdr.Length == 0 {
			// this is just empty zeros padding which AWS decided was OK..
			return tlvs, remainder, nil
		}

		tlvs = append(tlvs, tlv)

		remainder -= tlvLen
		tlvTotal += tlvLen
	}

	return tlvs, tlvTotal, nil
}
