package toyls

import (
	"io"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestConnHandleFragment(c *C) {
	conn := Conn{}
	in := &mockConnIOReaderWriter{read: []byte{22, 0x03, 0x01, 0x00, 0x01, 0x00}}
	cipherText, _ := conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS10)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToySuite) TestConnHandleCipherText(c *C) {
	conn := Conn{}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      3,
		fragment:    []byte{0x01, 0x02, 0x03},
	}
	conn.params = SecurityParameters{}
	conn.params.mac_length = 1
	conn.params.cipher = mockStreamCipher{}

	compressed, _ := conn.handleCipherText(cipherText)

	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

type mockStreamCipher struct{}

func (mockStreamCipher) XORKeyStream(dst, src []byte) {
	return
}

func (s *ToySuite) TestConnHandleCompressed(c *C) {
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

func (s *ToySuite) TestGenericStreamCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericStreamCipher{
		content: []byte{0x02},       //TLSCompressed.length
		MAC:     []byte{0x03, 0x01}, //SecurityParameters.mac_length
	}
	params := SecurityParameters{
		mac_length: 2,
	}
	c.Assert(GenericStreamCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericBlockCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericBlockCipher{
		IV:             []byte{0x01, 0x01}, //SecurityParameters.record_iv_length
		content:        []byte{0x02},       //TLSCompressed.length
		MAC:            []byte{0x03},       //SecurityParameters.mac_length
		padding:        []byte{0x04, 0x05}, //GenericBlockCipher.padding_length
		padding_length: 2,
	}
	params := SecurityParameters{
		record_iv_length: 2,
		mac_length:       1,
	}
	c.Assert(GenericBlockCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericAEADCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericAEADCipher{
		nonce_explicit: []byte{0x02, 0x01}, //SecurityParameters.record_iv_length
		content:        []byte{0x03},       //TLSCompressed.length
	}
	params := SecurityParameters{
		record_iv_length: 2,
	}
	c.Assert(GenericAEADCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
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
