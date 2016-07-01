package toyls

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

type Conn struct {
	state  connectionState
	params securityParameters
}

func NewConn() *Conn {
	conn := Conn{
		params: securityParameters{
			cipher: nullStreamCipher{},
			mac_algorithm: macAlgorithm{
				h: sha256.New(),
			},
			compression_algorithm: nullCompressionMethod{},
		},
	}
	return &conn
}

func (c *Conn) send(plain TLSPlaintext) []byte {
	compressed, _ := c.compress(plain)
	cipherText, _ := c.macAndEncrypt(compressed)
	return cipherText.serialize()
}

func (c *Conn) receive(payload []byte) {
	var cipherText TLSCiphertext
	for len(payload) > 0 {
		cipherText, payload, _ = c.handleFragment(payload)
		compressed, _ := c.handleCipherText(cipherText)
		plaintext, _ := c.handleCompressed(compressed)
		c.handlePlainText(plaintext)
	}
	return
}

func (c *Conn) handleFragment(payload []byte) (TLSCiphertext, []byte, error) {
	cipherText := TLSCiphertext{}
	header := make([]byte, 5)
	n := copy(header, payload)
	payload = payload[n:]
	cipherText.contentType = ContentType(header[0])
	cipherText.version, header = extractProtocolVersion(header[1:])
	cipherText.length, header = extractUint16(header)
	cipherText.fragment = make([]byte, cipherText.length)
	n = copy(cipherText.fragment, payload)
	payload = payload[n:]
	return cipherText, payload, nil
}

func (c *Conn) handleCipherText(cipherText TLSCiphertext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = cipherText.contentType
	compressed.version = cipherText.version
	var ciphered Ciphered
	switch c.params.cipher.(type) {
	case cipher.Stream:
		c.params.cipher.(cipher.Stream).XORKeyStream(cipherText.fragment, cipherText.fragment)
		ciphered = GenericStreamCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	case cipher.Block:
		ciphered = GenericBlockCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	case cipher.AEAD:
		ciphered = GenericAEADCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	}
	localMAC := c.params.mac_algorithm.MAC(nil, c.state.sequence_number[0:], cipherText.header(), ciphered.Content())
	remoteMAC := ciphered.Mac()
	if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 {
		return compressed, errors.New("MAC error")
	}
	compressed.fragment = ciphered.Content()
	compressed.length = uint16(len(compressed.fragment))
	return compressed, nil
}

func (c *Conn) macAndEncrypt(compressed TLSCompressed) (TLSCiphertext, error) {
	cipherText := TLSCiphertext{
		contentType: compressed.contentType,
		version:     compressed.version,
		length:      uint16(len(compressed.fragment) + c.params.mac_algorithm.Size()),
	}
	var ciphered Ciphered

	switch c.params.cipher.(type) {
	case cipher.Stream:
		ciphered = GenericStreamCipher{
			content: compressed.fragment, //TLSCompressed.length
			MAC:     c.params.mac_algorithm.MAC(nil, c.state.sequence_number[0:], cipherText.header(), compressed.fragment),
		}
		cipherText.fragment = ciphered.Marshal()
		c.params.cipher.(cipher.Stream).XORKeyStream(cipherText.fragment, cipherText.fragment)
		break
	case cipher.Block:
	case cipher.AEAD:
		return cipherText, errors.New("not Implemented")
	}
	return cipherText, nil
}

func (c *Conn) handleCompressed(compressed TLSCompressed) (TLSPlaintext, error) {
	plaintext := TLSPlaintext{}
	plaintext.contentType = compressed.contentType
	plaintext.version = compressed.version
	plaintext.fragment, plaintext.length = c.params.compression_algorithm.decompress(compressed.fragment)
	return plaintext, nil
}

func (c *Conn) compress(plaintext TLSPlaintext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = plaintext.contentType
	compressed.version = plaintext.version
	compressed.fragment, compressed.length = c.params.compression_algorithm.compress(plaintext.fragment)
	return compressed, nil
}

func (c *Conn) handlePlainText(plaintext TLSPlaintext) {
	//TODO: to be implemented
	return
}
