package toyls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const recordHeaderLen = 5

func Dial(network, addr string) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr)
}

func DialWithDialer(dialer *net.Dialer, network, addr string) (*Conn, error) {
	rawConn, err := dialer.Dial(network, addr)
	conn := NewConn(CLIENT)
	conn.rawConn = rawConn
	conn.doHandshake()
	return conn, err
}

type Conn struct {
	state  connectionState
	params securityParameters
	wp     writeParams

	handshaker
	chunkSize uint16

	rawConn     net.Conn
	calledClose int
}

func newClient() *Conn {
	return NewConn(CLIENT)
}

func newServer() *Conn {
	return NewConn(SERVER)
}

func NewConn(entity connectionEnd) *Conn {
	conn := Conn{
		state: connectionState{
			readSequenceNumber:  [8]byte{},
			writeSequenceNumber: [8]byte{},
		},
		params: securityParameters{
			entity:               entity,
			inCipher:             nullStreamCipher{},
			outCipher:            nullStreamCipher{},
			macAlgorithm:         nullMacAlgorithm{},
			compressionAlgorithm: nullCompressionMethod{},
			encKeyLength:         32,
			fixedIVLength:        16,
			macKeyLength:         32,
		},
		chunkSize: uint16(0x4000),
	}

	switch entity {
	case CLIENT:
		conn.handshaker = &handshakeClient{
			recordProtocol: &conn,
		}
	case SERVER:
		conn.handshaker = &handshakeServer{
			recordProtocol: &conn,
		}
	}

	return &conn
}

func (c *Conn) SetChunkSize(chunkSize uint16) {
	if chunkSize < uint16(0x4000) {
		c.chunkSize = chunkSize
	}
}

func (c Conn) Close() {
	c.rawConn.Close()
	return
}

func (c Conn) writeRecord(contentType ContentType, content []byte) error {
	var err error
	payload := []byte{}
	var plainText TLSPlaintext

	for len(content) > 0 {
		plainText, content, err = c.fragment(contentType, VersionTLS12, content)
		if err != nil {
			return err
		}

		compressed, err := c.compress(plainText)
		if err != nil {
			return err
		}

		cipherText, err := c.macAndEncrypt(compressed)
		if err != nil {
			return err
		}

		seq := binary.BigEndian.Uint64(c.state.writeSequenceNumber[:]) //TODO: alert for renegotiation
		binary.BigEndian.PutUint64(c.state.writeSequenceNumber[:], seq+1)
		payload = append(payload, cipherText.serialize()...)
	}
	c.rawConn.Write(payload)

	return nil
}

func (c Conn) readRecord(contentType ContentType) ([]byte, error) {
	cipherText, err := c.handleFragment(c.rawConn)
	if err != nil {
		panic(err)
	}
	compressed, err := c.handleCipherText(cipherText)
	if err != nil {
		panic(err)
	}
	plainText, err := c.handleCompressed(compressed)
	if err != nil {
		panic(err)
	}
	seq := binary.BigEndian.Uint64(c.state.readSequenceNumber[:]) //TODO: alert for renegotiation
	binary.BigEndian.PutUint64(c.state.readSequenceNumber[:], seq+1)
	if plainText.contentType != contentType {
		return plainText.fragment, fmt.Errorf("received unexpected message, %+v", plainText)
	}
	return plainText.fragment, nil
}

func (c *Conn) fragment(contentType ContentType, version protocolVersion, content []byte) (TLSPlaintext, []byte, error) {
	plainText := TLSPlaintext{
		contentType: contentType,
		version:     version,
	}
	length := len(content)
	if length > int(c.chunkSize) {
		plainText.length = c.chunkSize
		plainText.fragment = content[:c.chunkSize]
		content = content[c.chunkSize:]
	} else {
		plainText.length = uint16(length)
		plainText.fragment = content
		return plainText, nil, nil
	}
	return plainText, content, nil
}

func (c *Conn) handleFragment(in io.Reader) (TLSCiphertext, error) {
	cipherText := TLSCiphertext{}
	header, err := readFromUntil(in, 5)
	if err != nil {
		return cipherText, err
	}
	cipherText.contentType = ContentType(header[0])
	cipherText.version, header = extractProtocolVersion(header[1:])
	cipherText.length, header = extractUint16(header)
	cipherText.fragment, err = readFromUntil(in, int(cipherText.length))

	if err != nil {
		return cipherText, err
	}
	return cipherText, nil
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
	localMAC := c.params.macAlgorithm.MAC(nil, c.state.readSequenceNumber[0:], cipherText.header(), ciphered.Content())
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
			MAC:     c.params.macAlgorithm.MAC(nil, c.state.writeSequenceNumber[0:], cipherText.header(), compressed.fragment),
		}
		cipherText.fragment = ciphered.Marshal()
		cipherText.length = uint16(len(cipherText.fragment))
		c.params.outCipher.(cipher.Stream).XORKeyStream(cipherText.fragment, cipherText.fragment)
		break
	case cbcMode:
		ciphered := GenericBlockCipher{
			content: compressed.fragment,
			MAC:     c.params.macAlgorithm.MAC(nil, c.state.writeSequenceNumber[0:], cipherText.header(), compressed.fragment),
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
	plainText := TLSPlaintext{}
	plainText.contentType = compressed.contentType
	plainText.version = compressed.version
	plainText.fragment, plainText.length = c.params.compressionAlgorithm.decompress(compressed.fragment)
	return plainText, nil
}

func (c *Conn) compress(plainText TLSPlaintext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = plainText.contentType
	compressed.version = plainText.version
	compressed.fragment, compressed.length = c.params.compressionAlgorithm.compress(plainText.fragment)
	return compressed, nil
}

func (c *Conn) prepareCipherSpec(writeParameters writeParams) {
	//"in" uses the server (their), "out" uses the client (our)
	block, err := aes.NewCipher(writeParameters.clientKey)
	if err != nil {
		panic(err)
	}
	c.params.outCipher = cipher.NewCBCEncrypter(block, writeParameters.clientIV)

	block, err = aes.NewCipher(writeParameters.serverKey)
	if err != nil {
		panic(err)
	}
	c.params.inCipher = cipher.NewCBCDecrypter(block, writeParameters.serverIV)

	c.params.recordIVLength = uint8(c.params.outCipher.(cbcMode).BlockSize())

	//XXX this is probably not used
	c.wp = writeParameters
}

//This should establish the next (pending) write and read state
func (c *Conn) establishKeys(masterSecret [48]byte, clientRandom, serverRandom [32]byte) {
	//XXX This wont work until it sets the pending parameters
	return

	//XXX This should be the pending securityParameters
	c.params = securityParameters{
		entity: c.params.entity, //???

		masterSecret: masterSecret,
		clientRandom: clientRandom,
		serverRandom: serverRandom,

		//XXX This is all fixed to use TLS_RSA_WITH_AES_128_CBC_SHA256
		// This should create the correct securityParameters depending on the cipher suite
		macAlgorithm:         hmacAlgorithm{sha256.New()},
		compressionAlgorithm: nullCompressionMethod{},
		encKeyLength:         32,
		fixedIVLength:        16,
		macKeyLength:         32,
	}

	c.prepareCipherSpec(keysFromMasterSecret(c.params))
}

func readFromUntil(in io.Reader, i int) ([]byte, error) {
	ret := make([]byte, i)
	m := 0
	temp := ret[:]
	for {
		if m < i {
			n, err := in.Read(temp)
			if err, ok := err.(*net.OpError); ok && err.Timeout() {
				continue
			} else if err != nil {
				return nil, err
			}
			m += n
			temp = ret[m:]
		} else {
			break
		}
	}
	return ret, nil
}
