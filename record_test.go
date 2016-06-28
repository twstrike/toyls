package tls

import (
	"io"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ToylsSuite struct{}

var _ = Suite(&ToylsSuite{})

func (s *ToylsSuite) TestConnHandleFragment(c *C) {
	conn := Conn{}
	in := &mockConnIOReaderWriter{read: []byte{22, 0x03, 0x01, 0x00, 0x01, 0x00}}
	cipherText, _ := conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS10)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToylsSuite) TestConnHandleCipherText(c *C) {
	conn := Conn{}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}
	conn.params = SecurityParameters{}
	conn.params.mac_key_length = 0
	compressed, _ := conn.handleCipherText(cipherText)

	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToylsSuite) TestConnHandleCompressed(c *C) {
	conn := Conn{}
	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      3,
		fragment:    []byte{0x01, 0x02, 0x03},
	}
	conn.params = SecurityParameters{}
	conn.params.compression_algorithm = nullCompressionMethod{}
	plaintext, _ := conn.handleCompressed(compressed)

	c.Assert(plaintext.contentType, Equals, HANDSHAKE)
	c.Assert(plaintext.version, Equals, VersionTLS12)
	c.Assert(plaintext.length, Equals, uint16(3))
	c.Assert(plaintext.fragment, DeepEquals, []byte{0x01, 0x02, 0x03})
}

type mockConnIOReaderWriter struct {
	read      []byte
	readIndex int
	write     []byte
	errCount  int
	err       error

	calledClose int
}

func (iom *mockConnIOReaderWriter) Read(p []byte) (n int, err error) {
	if iom.readIndex >= len(iom.read) {
		return 0, io.EOF
	}
	i := copy(p, iom.read[iom.readIndex:])
	iom.readIndex += i
	var e error
	if iom.errCount == 0 {
		e = iom.err
	}
	iom.errCount--
	return i, e
}

func (iom *mockConnIOReaderWriter) Write(p []byte) (n int, err error) {
	iom.write = append(iom.write, p...)
	var e error
	if iom.errCount == 0 {
		e = iom.err
	}
	iom.errCount--
	return len(p), e
}

func (iom *mockConnIOReaderWriter) Close() error {
	iom.calledClose++
	return nil
}
