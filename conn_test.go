package toyls

import (
	"io"

	. "gopkg.in/check.v1"
)

func dummyClientAndServer() (*Conn, *Conn) {
	connA := NewConn(CLIENT)
	connB := NewConn(SERVER)

	keys := keysFromMasterSecret(securityParameters{
		encKeyLength:  32,
		fixedIVLength: 16,
		macKeyLength:  32,

		masterSecret: [48]byte{
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		},
		clientRandom: [32]byte{
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		},
		serverRandom: [32]byte{
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		},
	})

	connA.prepareCipherSpec(keys)
	connB.prepareCipherSpec(keys)

	//TODO: REMOVE ME after the IV is random
	connA.wp = keys
	connB.wp = keys

	connA.changeWriteCipherSpec()
	connB.changeReadCipherSpec()

	//XXX It does not work if we have a mac
	connA.write.mac = nullMacAlgorithm{}
	connB.read.mac = nullMacAlgorithm{}

	return connA, connB
}

func (s *ToySuite) TestConnHandleFragment(c *C) {
	conn := NewConn(CLIENT)
	in := &mockConnIOReaderWriter{readwrite: []byte{22, 0x03, 0x03, 0x00, 0x01, 0x00, 22, 0x03, 0x03, 0x00, 0x01, 0x00}}
	cipherText, _ := conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS12)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})

	cipherText, _ = conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS12)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToySuite) TestConnHandleStreamCipherText(c *C) {
	c.Skip("Not implemented yet")

	conn := NewConn(CLIENT)
	conn.read.mac = nullMacAlgorithm{}

	ciphered := GenericStreamCipher{
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = conn.read.mac.MAC(nil, conn.state.writeSequenceNumber[0:], cipherText.header(), ciphered.content)

	cipherText.fragment = ciphered.Marshal()
	cipherText.length = uint16(len(cipherText.fragment))

	compressed, err := conn.handleCipherText(cipherText)

	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnHandleBlockCipherText(c *C) {
	_, connB := dummyClientAndServer()

	cipherText := TLSCiphertext{
		contentType: 0x16,
		version:     VersionTLS12,
		//protocolVersion{major: 0x3, minor: 0x3},
		length: 0x20,
		fragment: []uint8{
			0x28, 0x33, 0x45, 0x42, 0xfe, 0x43, 0xc3, 0x65,
			0x2, 0x19, 0x77, 0x2a, 0x41, 0xc0, 0x5a, 0x39,
			0xfb, 0x72, 0x8a, 0x40, 0x0, 0xc2, 0x9a, 0xbc,
			0xc2, 0x3d, 0x44, 0xd5, 0x86, 0x56, 0x76, 0x33,
		},
	}
	compressed, err := connB.handleCipherText(cipherText)

	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnHandleCompressed(c *C) {
	conn := NewConn(CLIENT)
	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      3,
		fragment:    []byte{0x01, 0x02, 0x03},
	}

	conn.read.compression = nullCompressionMethod{}
	plaintext, err := conn.handleCompressed(compressed)
	c.Assert(err, IsNil)

	c.Assert(plaintext.contentType, Equals, HANDSHAKE)
	c.Assert(plaintext.version, Equals, VersionTLS12)
	c.Assert(plaintext.length, Equals, uint16(3))
	c.Assert(plaintext.fragment, DeepEquals, []byte{0x01, 0x02, 0x03})
}

func (s *ToySuite) TestConnStreamMacAndEncrypt(c *C) {
	c.Skip("not implemented")

	conn := NewConn(CLIENT)
	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}
	cipherText, err := conn.macAndEncrypt(compressed)
	c.Assert(err, IsNil)
	compressed, err = conn.handleCipherText(cipherText)
	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnBlockMacAndEncrypt(c *C) {
	client, server := dummyClientAndServer()
	expected := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}

	cipherText, err := client.macAndEncrypt(expected)
	c.Assert(err, IsNil)

	compressed, err := server.handleCipherText(cipherText)
	c.Assert(err, IsNil)

	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, expected.length)
	c.Assert(compressed.fragment, DeepEquals, expected.fragment)
}

func (s *ToySuite) TestConnFragment(c *C) {
	conn := NewConn(CLIENT)
	conn.SetChunkSize(uint16(0x3000))
	content := [0x5000]byte{}
	plainText, in, _ := conn.fragment(HANDSHAKE, VersionTLS12, content[:])
	c.Assert(plainText.contentType, Equals, HANDSHAKE)
	c.Assert(plainText.version, Equals, VersionTLS12)
	c.Assert(plainText.length, Equals, uint16(0x3000))
	c.Assert(len(plainText.fragment), Equals, int(0x3000))

	plainText, in, _ = conn.fragment(HANDSHAKE, VersionTLS12, in)
	c.Assert(plainText.contentType, Equals, HANDSHAKE)
	c.Assert(plainText.version, Equals, VersionTLS12)
	c.Assert(plainText.length, Equals, uint16(0x2000))
	c.Assert(len(plainText.fragment), Equals, int(0x2000))
}

type mockConnIOReaderWriter struct {
	readwrite []byte
	readIndex int
	errCount  int
	err       error

	calledClose int
}

func (iom *mockConnIOReaderWriter) Read(p []byte) (n int, err error) {
	if iom.readIndex >= len(iom.readwrite) {
		return 0, io.EOF
	}
	i := copy(p, iom.readwrite[iom.readIndex:])
	iom.readIndex += i
	var e error
	if iom.errCount == 0 {
		e = iom.err
	}
	iom.errCount--
	return i, e
}

func (iom *mockConnIOReaderWriter) Write(p []byte) (n int, err error) {
	iom.readwrite = append(iom.readwrite, p...)
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
