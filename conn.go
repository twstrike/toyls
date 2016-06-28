package tls

import (
	"encoding/binary"
	"io"
)

type Conn struct {
	state  ConnectionState
	params SecurityParameters
}

func (c *Conn) receive(in io.Reader) TLSPlaintext {
	cipherText, _ := c.handleFragment(in)
	compressed, _ := c.handleCipherText(cipherText)
	plaintext, _ := c.handleCompressed(compressed)
	return plaintext
}

func (c *Conn) handleFragment(in io.Reader) (TLSCiphertext, error) {
	cipherText := TLSCiphertext{}
	header := make([]byte, 5)
	in.Read(header)
	cipherText.contentType = ContentType(header[0])
	cipherText.version = ProtocolVersion{header[1], header[2]}
	cipherText.length = binary.BigEndian.Uint16(header[3:])
	cipherText.fragment = make([]byte, cipherText.length)
	in.Read(cipherText.fragment)
	return cipherText, nil
}

func (c *Conn) handleCipherText(cipherText TLSCiphertext) (TLSCompressed, error) {
	//TODO: MAC.verify(conn.state.mac_key,cipherText.fragment[:])
	compressed := TLSCompressed{}
	compressed.contentType = cipherText.contentType
	compressed.version = cipherText.version
	compressed.length = uint16(len(cipherText.fragment)) - uint16(c.params.mac_length)
	//TODO: This is not correct when using Block and AEAD ciphers
	compressed.fragment = make([]byte, compressed.length)
	copy(compressed.fragment, cipherText.fragment)
	return compressed, nil
}

func (c *Conn) handleCompressed(compressed TLSCompressed) (TLSPlaintext, error) {
	plaintext := TLSPlaintext{}
	plaintext.contentType = compressed.contentType
	plaintext.version = compressed.version
	plaintext.fragment, plaintext.length = c.params.compression_algorithm.decompress(compressed.fragment)
	return plaintext, nil
}
