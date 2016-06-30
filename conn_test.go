package toyls

import (
	"crypto/sha256"

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
	conn := Conn{
		params: SecurityParameters{
			cipher: mockStreamCipher{},
			mac_algorithm: MACAlgorithm{
				h: sha256.New(),
			},
		},
	}
	ciphered := GenericStreamCipher{
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content) + conn.params.mac_algorithm.Size()),
	}
	header := cipherText.header()
	ciphered.MAC = conn.params.mac_algorithm.MAC(nil, conn.state.sequence_number[0:], header[:], ciphered.content)
	cipherText.fragment = ciphered.Marshal()
	compressed, err := conn.handleCipherText(cipherText)

	c.Assert(err, IsNil)
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
