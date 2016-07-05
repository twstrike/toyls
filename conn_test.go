package toyls

import (
	"crypto/aes"
	"crypto/cipher"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestConnHandleFragment(c *C) {
	conn := NewConn(CLIENT)
	in := []byte{22, 0x03, 0x01, 0x00, 0x01, 0x00, 22, 0x03, 0x01, 0x00, 0x01, 0x00}
	cipherText, in, _ := conn.handleFragment(in)
	cipherText, in, _ = conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS10)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToySuite) TestConnHandleStreamCipherText(c *C) {
	conn := NewConn(CLIENT)
	ciphered := GenericStreamCipher{
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = conn.params.macAlgorithm.MAC(nil, conn.state.writeSequenceNumber[0:], cipherText.header(), ciphered.content)

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
	connA := NewConn(CLIENT)
	connB := NewConn(SERVER)
	connA.params.masterSecret = [48]byte{0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	wp := keysFromMasterSecret(connA.params)
	block, err := aes.NewCipher(wp.clientKey)

	connA.params.outCipher = cipher.NewCBCEncrypter(block, wp.clientIV)
	connB.params.inCipher = cipher.NewCBCDecrypter(block, wp.clientIV)
	connA.params.recordIVLength = uint8(connA.params.outCipher.(cbcMode).BlockSize())
	connB.params.recordIVLength = uint8(connB.params.inCipher.(cbcMode).BlockSize())

	ciphered := GenericBlockCipher{
		IV:      wp.clientIV,
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = connA.params.macAlgorithm.MAC(nil, connA.state.writeSequenceNumber[0:], cipherText.header(), ciphered.content)

	ciphered.padToBlockSize(connA.params.outCipher.(cbcMode).BlockSize())

	cipherText.fragment = make([]byte, len(ciphered.Marshal()))
	copy(cipherText.fragment, ciphered.IV)

	connA.params.outCipher.(cbcMode).CryptBlocks(cipherText.fragment[connA.params.recordIVLength:], ciphered.Marshal()[connA.params.recordIVLength:])
	cipherText.length = uint16(len(cipherText.fragment))

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
	plaintext, _ := conn.handleCompressed(compressed)

	c.Assert(plaintext.contentType, Equals, HANDSHAKE)
	c.Assert(plaintext.version, Equals, VersionTLS12)
	c.Assert(plaintext.length, Equals, uint16(3))
	c.Assert(plaintext.fragment, DeepEquals, []byte{0x01, 0x02, 0x03})
}

func (s *ToySuite) TestConnStreamMacAndEncrypt(c *C) {
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
	connA := NewConn(CLIENT)
	connB := NewConn(SERVER)
	connA.params.masterSecret = [48]byte{0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	wp := keysFromMasterSecret(connA.params)
	connA.wp = wp
	block, err := aes.NewCipher(wp.clientKey)
	connA.params.outCipher = cipher.NewCBCEncrypter(block, wp.clientIV)
	connB.params.inCipher = cipher.NewCBCDecrypter(block, wp.clientIV)
	connA.params.recordIVLength = uint8(connA.params.outCipher.(cbcMode).BlockSize())
	connB.params.recordIVLength = uint8(connB.params.inCipher.(cbcMode).BlockSize())

	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}
	cipherText, err := connA.macAndEncrypt(compressed)
	c.Assert(err, IsNil)
	compressed, err = connB.handleCipherText(cipherText)
	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
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
