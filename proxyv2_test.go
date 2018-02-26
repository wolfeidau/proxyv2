package proxyv2

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldReadSignature(t *testing.T) {

	buf := bytes.NewBuffer(signature)

	readSig, err := checkSignature(buf)

	require.NoError(t, err)
	require.Equal(t, 12, len(readSig))

	require.Equal(t, signature, readSig)
}

func TestShouldReadSignatureAndReturnErrNotFound(t *testing.T) {

	buf := bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})

	readSig, err := checkSignature(buf)

	require.Equal(t, errSignatureNotMatched, err)
	require.Nil(t, readSig)
}

func TestShouldReadSignatureAndReturnEOF(t *testing.T) {

	buf := bytes.NewBuffer([]byte{})

	readSig, err := checkSignature(buf)

	require.Equal(t, io.EOF, err)
	require.Nil(t, readSig)
}

func TestShouldParseHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{33, 17, 0, 12, 172, 18, 0, 4, 172, 18, 0, 3, 223, 64, 35, 40})
	state, err := readV2Info(buf)
	require.Nil(t, err)

	err = state.Parse()
	require.Nil(t, err)
}

func TestShouldReadListOfTLV(t *testing.T) {

	tlvData := []byte{32, 0, 16, 1, 0, 0, 0, 0, 33, 0, 8, 84, 76, 83, 118, 49, 46, 50, 0}

	tlv, read, err := readTLV(bytes.NewBuffer(tlvData))
	require.Nil(t, err)

	//fmt.Println(tlv)

	require.Equal(t, &ProxyTLVHeader{Type: 0x20, Length: 0x10}, tlv.Hdr)
	require.Equal(t, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x21, 0x0, 0x8, 0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x32, 0x0}, tlv.Data)
	require.Equal(t, 19, read)

}

func TestShouldReadListOfTLVs(t *testing.T) {
	tlvData := []byte{32, 0, 16, 1, 0, 0, 0, 0, 33, 0, 8, 84, 76, 83, 118, 49, 46, 50, 0}

	tlvs, read, err := readTLVs(bytes.NewBuffer(tlvData), 19)
	require.Nil(t, err)

	//fmt.Println(tlvs)

	require.Equal(t, &ProxyTLVHeader{Type: 0x20, Length: 0x10}, tlvs[0].Hdr)
	require.Equal(t, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x21, 0x0, 0x8, 0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x32, 0x0}, tlvs[0].Data)
	require.Equal(t, 19, read)

}
