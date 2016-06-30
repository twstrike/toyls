package toyls

import (
	"crypto/sha256"
	"io"

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
	params := SecurityParameters{
		mac_algorithm: MACAlgorithm{
			h: sha256.New(),
		},
	}
	ciphered := GenericStreamCipher{
		content: []byte{0x02},                              //TLSCompressed.length
		MAC:     make([]byte, params.mac_algorithm.Size()), //SecurityParameters.mac_length
	}
	c.Assert(GenericStreamCipher{}.UnMarshal(ciphered.Marshal(), params), DeepEquals, ciphered)
}

func (s *ToySuite) TestGenericBlockCipherMarshalAndUnMarshal(c *C) {
	params := SecurityParameters{
		record_iv_length: 2,
		mac_algorithm: MACAlgorithm{
			h: sha256.New(),
		},
	}
	ciphered := GenericBlockCipher{
		IV:             []byte{0x01, 0x01},                        //SecurityParameters.record_iv_length
		content:        []byte{0x02},                              //TLSCompressed.length
		MAC:            make([]byte, params.mac_algorithm.Size()), //SecurityParameters.mac_length
		padding:        []byte{0x04, 0x05},                        //GenericBlockCipher.padding_length
		padding_length: 2,
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
