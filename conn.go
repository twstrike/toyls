package toyls

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"
)

type Conn struct {
	state  ConnectionState
	params SecurityParameters
}

func (c *Conn) receive(in io.Reader) TLSPlaintext {
	cipherText, _ := c.handleFragment(in)
	switch cipherText.contentType {

	}
	compressed, _ := c.handleCipherText(cipherText)
	plaintext, _ := c.handleCompressed(compressed)
	return plaintext
}

func (c *Conn) handleFragment(in io.Reader) (TLSCiphertext, error) {
	cipherText := TLSCiphertext{}
	header := make([]byte, 5)
	in.Read(header)
	cipherText.contentType = ContentType(header[0])
	cipherText.version, header = extractProtocolVersion(header[1:])
	cipherText.length, header = extractUint16(header)
	cipherText.fragment = make([]byte, cipherText.length)
	in.Read(cipherText.fragment)
	return cipherText, nil
}

func (c *Conn) handleCipherText(cipherText TLSCiphertext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = cipherText.contentType
	compressed.version = cipherText.version
	//TODO: MAC.verify(conn.state.mac_key,cipherText.fragment[:])
	switch c.params.cipher.(type) {
	case cipher.Stream:
		c.params.cipher.(cipher.Stream).XORKeyStream(cipherText.fragment, cipherText.fragment)
		ciphered := GenericStreamCipher{}.UnMarshal(cipherText.fragment, c.params)
		localMAC := c.params.mac_algorithm.MAC(nil, c.state.sequence_number[0:], cipherText.header(), ciphered.content)
		compressed.length = uint16(len(ciphered.content))
		compressed.fragment = ciphered.content
		if subtle.ConstantTimeCompare(localMAC, ciphered.MAC) != 1 {
			return compressed, errors.New("MAC error")
		}
	case cipher.Block:
		ciphered := GenericBlockCipher{}.UnMarshal(cipherText.fragment, c.params)
		compressed.length = uint16(len(ciphered.content))
		compressed.fragment = ciphered.content
	case cipher.AEAD:
		ciphered := GenericAEADCipher{}.UnMarshal(cipherText.fragment, c.params)
		compressed.length = uint16(len(ciphered.content))
		compressed.fragment = ciphered.content
	}
	return compressed, nil
}

func (c *Conn) handleCompressed(compressed TLSCompressed) (TLSPlaintext, error) {
	plaintext := TLSPlaintext{}
	plaintext.contentType = compressed.contentType
	plaintext.version = compressed.version
	plaintext.fragment, plaintext.length = c.params.compression_algorithm.decompress(compressed.fragment)
	return plaintext, nil
}
