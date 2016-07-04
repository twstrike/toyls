package toyls

import (
	"crypto/aes"
	"crypto/cipher"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestConnHandleFragment(c *C) {
	conn := NewConn()
	in := []byte{22, 0x03, 0x01, 0x00, 0x01, 0x00, 22, 0x03, 0x01, 0x00, 0x01, 0x00}
	cipherText, in, _ := conn.handleFragment(in)
	cipherText, in, _ = conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS10)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToySuite) TestConnHandleStreamCipherText(c *C) {
	conn := NewConn()
	ciphered := GenericStreamCipher{
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = conn.params.macAlgorithm.MAC(nil, conn.state.sequenceNumber[0:], cipherText.header(), ciphered.content)

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
	connA := NewConn()
	connB := NewConn()
	connA.params.masterSecret = [48]byte{0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	wp := keysFromMasterSecret(connA.params)
	block, err := aes.NewCipher(wp.clientKey)

	connA.params.cipher = cipher.NewCBCEncrypter(block, wp.clientIV)
	connB.params.cipher = cipher.NewCBCDecrypter(block, wp.clientIV)
	connA.params.recordIVLength = uint8(connA.params.cipher.(cbcMode).BlockSize())
	connB.params.recordIVLength = uint8(connB.params.cipher.(cbcMode).BlockSize())

	ciphered := GenericBlockCipher{
		IV:      make([]byte, connA.params.recordIVLength),
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = connA.params.macAlgorithm.MAC(nil, connA.state.sequenceNumber[0:], cipherText.header(), ciphered.content)

	ciphered.SetIV(wp.clientIV)
	ciphered.padToBlockSize(connA.params.cipher.(cbcMode).BlockSize())

	cipherText.fragment = make([]byte, len(ciphered.Marshal()))
	copy(cipherText.fragment, ciphered.IV)

	remaining := make([]byte, len(cipherText.fragment)-int(connA.params.recordIVLength))
	plain := ciphered.Marshal()[connA.params.recordIVLength:]

	connA.params.cipher.(cbcMode).CryptBlocks(remaining, plain)
	plain = make([]byte, len(remaining))
	connB.params.cipher.(cbcMode).CryptBlocks(plain, remaining)

	copy(cipherText.fragment[connA.params.recordIVLength:], remaining)
	cipherText.length = uint16(len(cipherText.fragment))

	compressed, err := connB.handleCipherText(cipherText)

	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnHandleCompressed(c *C) {
	conn := NewConn()
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

func (s *ToySuite) TestConnMacAndEncrypt(c *C) {
	conn := NewConn()
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
