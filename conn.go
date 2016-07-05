package toyls

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

const recordHeaderLen = 5

type Conn struct {
	state  connectionState
	params securityParameters
	wp     writeParams
}

func NewConn(entity connectionEnd) *Conn {
	conn := Conn{
		params: securityParameters{
			entity:    entity,
			inCipher:  nullStreamCipher{},
			outCipher: nullStreamCipher{},
			macAlgorithm: macAlgorithm{
				h: sha256.New(),
			},
			compressionAlgorithm: nullCompressionMethod{},
			encKeyLength:         32,
			fixedIVLength:        16,
			macKeyLength:         32,
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

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

func (c *Conn) handleCipherText(cipherText TLSCiphertext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = cipherText.contentType
	compressed.version = cipherText.version
	var ciphered Ciphered
	explicitIVLen := 0
	switch cc := c.params.inCipher.(type) {
	case cipher.Stream:
		cc.XORKeyStream(cipherText.fragment, cipherText.fragment)
		ciphered = GenericStreamCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	case cbcMode:
		blockSize := cc.BlockSize()
		explicitIVLen = blockSize
		if len(cipherText.fragment)%blockSize != 0 || len(cipherText.fragment) < roundUp(explicitIVLen+c.params.macAlgorithm.Size()+1, blockSize) {
			return compressed, errors.New("alertBadRecordMAC")
		}
		remaining := cipherText.fragment
		if explicitIVLen > 0 {
			cc.SetIV(cipherText.fragment[:explicitIVLen])
			remaining = cipherText.fragment[explicitIVLen:]
		}
		cc.CryptBlocks(remaining, remaining)
		copy(cipherText.fragment[explicitIVLen:], remaining)
		ciphered = GenericBlockCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	case cipher.AEAD:
		ciphered = GenericAEADCipher{}.UnMarshal(cipherText.fragment, c.params)
		break
	}
	cipherText.length = uint16(len(ciphered.Content()))
	localMAC := c.params.macAlgorithm.MAC(nil, c.state.sequenceNumber[0:], cipherText.header(), ciphered.Content())
	remoteMAC := ciphered.Mac()
	if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 {
		return compressed, errors.New("alertBadRecordMAC")
	}
	compressed.fragment = ciphered.Content()
	compressed.length = uint16(len(compressed.fragment))
	return compressed, nil
}

func (c *GenericBlockCipher) padToBlockSize(blockSize int) {
	payload := append(c.content, c.MAC...)
	overrun := len(payload) % blockSize
	c.padding_length = uint8(blockSize-overrun) - 1
	c.padding = make([]byte, c.padding_length)
	copy(c.padding, payload[len(payload)-overrun:])
	for i := overrun; i < blockSize-1; i++ {
		c.padding[i-overrun] = byte(c.padding_length)
	}
	return
}

func (c *Conn) macAndEncrypt(compressed TLSCompressed) (TLSCiphertext, error) {
	cipherText := TLSCiphertext{
		contentType: compressed.contentType,
		version:     compressed.version,
		length:      uint16(len(compressed.fragment)),
	}
	switch cc := c.params.outCipher.(type) {
	case cipher.Stream:
		ciphered := GenericStreamCipher{
			content: compressed.fragment, //TLSCompressed.length
			MAC:     c.params.macAlgorithm.MAC(nil, c.state.sequenceNumber[0:], cipherText.header(), compressed.fragment),
		}
		cipherText.fragment = ciphered.Marshal()
		c.params.outCipher.(cipher.Stream).XORKeyStream(cipherText.fragment, cipherText.fragment)
		break
	case cbcMode:
		ciphered := GenericBlockCipher{
			content: compressed.fragment,
			MAC:     c.params.macAlgorithm.MAC(nil, c.state.sequenceNumber[0:], cipherText.header(), compressed.fragment),
		}
		ciphered.IV = c.cbcIV(true)
		ciphered.padToBlockSize(cc.BlockSize())
		cipherText.fragment = make([]byte, len(ciphered.Marshal()))
		cipherText.length = uint16(len(cipherText.fragment))
		copy(cipherText.fragment, ciphered.IV)
		cc.CryptBlocks(cipherText.fragment[c.params.recordIVLength:], ciphered.Marshal()[c.params.recordIVLength:])
		break
	case cipher.AEAD:
		return cipherText, errors.New("not Implemented")
	}
	return cipherText, nil
}

func (c Conn) cbcIV(sending bool) (iv []byte) {
	if c.params.entity == CLIENT {
		if sending {
			iv = c.wp.clientIV
		} else {
			iv = c.wp.serverIV
		}
	} else if c.params.entity == SERVER {
		if sending {
			iv = c.wp.serverIV
		} else {
			iv = c.wp.clientIV
		}
	}
	return
}

func (c *Conn) handleCompressed(compressed TLSCompressed) (TLSPlaintext, error) {
	plaintext := TLSPlaintext{}
	plaintext.contentType = compressed.contentType
	plaintext.version = compressed.version
	plaintext.fragment, plaintext.length = c.params.compressionAlgorithm.decompress(compressed.fragment)
	return plaintext, nil
}

func (c *Conn) compress(plaintext TLSPlaintext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = plaintext.contentType
	compressed.version = plaintext.version
	compressed.fragment, compressed.length = c.params.compressionAlgorithm.compress(plaintext.fragment)
	return compressed, nil
}

func (c *Conn) handlePlainText(plaintext TLSPlaintext) {
	//TODO: to be implemented
	return
}
