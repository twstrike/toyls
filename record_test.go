package toyls

import . "gopkg.in/check.v1"

func (s *ToySuite) TestTLSCiphertextHeader(c *C) {
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS10,
		length:      1,
	}

	c.Assert(cipherText.header(), DeepEquals, []byte{22, 0x3, 0x1, 0x0, 0x1})
}

func (s *ToySuite) TestGenericStreamCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericStreamCipher{
		content: []byte{0x02},     //TLSCompressed.length
		MAC:     make([]byte, 32), //SecurityParameters.mac_length
	}
	c.Assert(GenericStreamCipher{}.UnMarshal(ciphered.Marshal(), 32), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericBlockCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericBlockCipher{
		IV:             make([]byte, 16),   //SecurityParameters.record_iv_length
		content:        []byte{0x02},       //TLSCompressed.length
		MAC:            make([]byte, 32),   //SecurityParameters.mac_length
		padding:        []byte{0x02, 0x02}, //GenericBlockCipher.padding_length
		padding_length: 2,
	}
	c.Assert(GenericBlockCipher{}.UnMarshal(ciphered.Marshal(), 16, 32), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericAEADCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericAEADCipher{
		nonce_explicit: make([]byte, 16), //SecurityParameters.record_iv_length
		content:        []byte{0x03},     //TLSCompressed.length
	}
	c.Assert(GenericAEADCipher{}.UnMarshal(ciphered.Marshal(), 16), DeepEquals, ciphered)
}
