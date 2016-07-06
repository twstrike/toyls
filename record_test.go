package toyls

import (
	"crypto/sha256"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestTLSCiphertextHeader(c *C) {
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS10,
		length:      1,
	}

	c.Assert(cipherText.header(), DeepEquals, []byte{22, 0x3, 0x1, 0x0, 0x1})
}

func (s *ToySuite) TestGenericStreamCipherMarshalAndUnMarshal(c *C) {
	params := securityParameters{
		macAlgorithm: hmacAlgorithm{
			h: sha256.New(),
		},
	}
	ciphered := GenericStreamCipher{
		content: []byte{0x02},                             //TLSCompressed.length
		MAC:     make([]byte, params.macAlgorithm.Size()), //SecurityParameters.mac_length
	}
	c.Assert(GenericStreamCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericBlockCipherMarshalAndUnMarshal(c *C) {
	params := securityParameters{
		recordIVLength: 2,
		macAlgorithm: hmacAlgorithm{
			h: sha256.New(),
		},
	}
	ciphered := GenericBlockCipher{
		IV:             []byte{0x01, 0x01},                       //SecurityParameters.record_iv_length
		content:        []byte{0x02},                             //TLSCompressed.length
		MAC:            make([]byte, params.macAlgorithm.Size()), //SecurityParameters.mac_length
		padding:        []byte{0x02, 0x02},                       //GenericBlockCipher.padding_length
		padding_length: 2,
	}
	c.Assert(GenericBlockCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericAEADCipherMarshalAndUnMarshal(c *C) {
	ciphered := GenericAEADCipher{
		nonce_explicit: []byte{0x02, 0x01}, //SecurityParameters.record_iv_length
		content:        []byte{0x03},       //TLSCompressed.length
	}
	params := securityParameters{
		recordIVLength: 2,
	}
	c.Assert(GenericAEADCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}
