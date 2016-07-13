package toyls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
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

type encryptionState struct {
	version     protocolVersion
	cipher      cipherType
	mac         macAlgorithm
	compression compressionMethod

	sequenceNumber [8]byte //uint64
}

type Conn struct {
	entity connectionEnd

	read, pendingRead   encryptionState
	write, pendingWrite encryptionState
	wp                  keyingMaterial

	handshaker
	chunkSize uint16

	rawConn     net.Conn
	calledClose int
	inbuf       bytes.Buffer
}

func newClient() *Conn {
	return NewConn(CLIENT)
}

func newServer() *Conn {
	return NewConn(SERVER)
}

func NewConn(entity connectionEnd) *Conn {
	conn := Conn{
		entity:    entity,
		chunkSize: uint16(0x4000),
		write: encryptionState{
			version:     VersionTLS12,
			cipher:      nullStreamCipher{},
			mac:         nullMacAlgorithm{},
			compression: nullCompressionMethod{},
		},
		read: encryptionState{
			version:     VersionTLS12,
			cipher:      nullStreamCipher{},
			mac:         nullMacAlgorithm{},
			compression: nullCompressionMethod{},
		},
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

func (c *Conn) Close() {
	c.rawConn.Close()
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n = 0
	for {
		m, err := c.inbuf.Read(b[n:])
		if err != nil && err != io.EOF {
			return n, err
		}
		n += m
		if n >= len(b) {
			break
		}
		data, err := c.readRecord(APPLICATION_DATA)
		if err != nil {
			return n, err
		}
		c.inbuf.Write(data)
	}
	return n, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if err := c.writeRecord(APPLICATION_DATA, b); err != nil {
		return len(b), err
	}
	return len(b), nil
}

func (c *Conn) writeRecord(contentType ContentType, content []byte) error {
	var err error
	var plainText TLSPlaintext

	for len(content) > 0 {
		plainText, content, err = c.fragment(contentType, c.write.version, content)
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

		seq := binary.BigEndian.Uint64(c.write.sequenceNumber[:]) //TODO: alert for renegotiation
		binary.BigEndian.PutUint64(c.write.sequenceNumber[:], seq+1)

		c.rawConn.Write(cipherText.serialize())
	}

	return nil
}

func (c *Conn) readRecord(contentType ContentType) ([]byte, error) {
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

	seq := binary.BigEndian.Uint64(c.read.sequenceNumber[:]) //TODO: alert for renegotiation
	binary.BigEndian.PutUint64(c.read.sequenceNumber[:], seq+1)
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

	macAlgorithm := c.read.mac

	switch cc := c.read.cipher.(type) {
	default:
		panic("unsupported")
	case cipher.Stream:
		cc.XORKeyStream(cipherText.fragment, cipherText.fragment)
		ciphered = GenericStreamCipher{}.UnMarshal(cipherText.fragment, macAlgorithm.Size())
	case cbcMode:
		blockSize := cc.BlockSize()
		explicitIVLen = blockSize

		if len(cipherText.fragment)%blockSize != 0 ||
			len(cipherText.fragment) < roundUp(explicitIVLen+macAlgorithm.Size()+1, blockSize) {
			return compressed, errors.New("alertBadRecordMAC")
		}

		remaining := cipherText.fragment
		if explicitIVLen > 0 {
			cc.SetIV(cipherText.fragment[:explicitIVLen])
			remaining = cipherText.fragment[explicitIVLen:]
		}
		cc.CryptBlocks(remaining, remaining)
		copy(cipherText.fragment[explicitIVLen:], remaining)
		ciphered = GenericBlockCipher{}.UnMarshal(cipherText.fragment, cc.BlockSize(), macAlgorithm.Size())

		//case cipher.AEAD:
		//	ciphered = GenericAEADCipher{}.UnMarshal(cipherText.fragment, c.securityParams)
		//	break
	}

	cipherText.length = uint16(len(ciphered.Content()))
	localMAC := macAlgorithm.MAC(nil, c.read.sequenceNumber[0:], cipherText.header(), ciphered.Content())
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

	macAlgorithm := c.write.mac

	switch cc := c.write.cipher.(type) {
	default:
		panic("unsupported")
	case cipher.Stream:
		ciphered := GenericStreamCipher{
			content: compressed.fragment, //TLSCompressed.length
			MAC:     macAlgorithm.MAC(nil, c.write.sequenceNumber[0:], cipherText.header(), compressed.fragment),
		}
		cipherText.fragment = ciphered.Marshal()
		cipherText.length = uint16(len(cipherText.fragment))
		cc.XORKeyStream(cipherText.fragment, cipherText.fragment)
	case cbcMode:
		ciphered := GenericBlockCipher{
			content: compressed.fragment,
			MAC:     macAlgorithm.MAC(nil, c.write.sequenceNumber[0:], cipherText.header(), compressed.fragment),
		}
		ciphered.IV = c.writeIV()
		ciphered.padToBlockSize(cc.BlockSize())

		cipherText.fragment = make([]byte, len(ciphered.Marshal()))
		cipherText.length = uint16(len(cipherText.fragment))
		copy(cipherText.fragment, ciphered.IV)
		cc.CryptBlocks(cipherText.fragment[cc.BlockSize():], ciphered.Marshal()[cc.BlockSize():])

		nextIV := make([]byte, cc.BlockSize())
		rand.Read(nextIV)
		cc.SetIV(nextIV)
		c.setWriteIV(nextIV)
		//case cipher.AEAD:
		//	return cipherText, errors.New("not Implemented")
	}

	return cipherText, nil
}

func (c *Conn) writeIV() []byte {
	switch c.entity {
	case CLIENT:
		return c.wp.clientIV
	case SERVER:
		return c.wp.serverIV
	default:
		panic("invalid entity")
	}

	return nil
}

func (c *Conn) setWriteIV(iv []byte) {
	//XXX is this correct? arent they generated from masterSecret, clientRandom and serverRandom?
	switch c.entity {
	case CLIENT:
		c.wp.clientIV = iv
	case SERVER:
		c.wp.serverIV = iv
	default:
		panic("invalid entity")
	}

	return
}

func (c *Conn) handleCompressed(compressed TLSCompressed) (TLSPlaintext, error) {
	plainText := TLSPlaintext{}
	plainText.contentType = compressed.contentType
	plainText.version = compressed.version
	plainText.fragment, plainText.length = c.read.compression.decompress(compressed.fragment)
	return plainText, nil
}

func (c *Conn) compress(plainText TLSPlaintext) (TLSCompressed, error) {
	compressed := TLSCompressed{}
	compressed.contentType = plainText.contentType
	compressed.version = plainText.version
	compressed.fragment, compressed.length = c.write.compression.compress(plainText.fragment)
	return compressed, nil
}

//XXX the input is not writeParameters because they are parameters for both reading and writing.
func (c *Conn) prepareCipherSpec(writeParameters keyingMaterial) {
	switch c.entity {
	case SERVER:
		c.prepareServerCipherSpec(writeParameters)
	case CLIENT:
		c.prepareClientCipherSpec(writeParameters)
	default:
		panic("unexpected entity value")
	}

	//It is only used because of conn.writeIV()
	//XXX Remove me after IV is random
	c.wp = keyingMaterial{
		clientIV: writeParameters.clientIV,
		serverIV: writeParameters.serverIV,
	}
}

func (c *Conn) prepareServerCipherSpec(writeParameters keyingMaterial) {
	//XXX This is all fixed to use TLS_RSA_WITH_AES_128_CBC_SHA
	compression := nullCompressionMethod{}
	readMac := hmacAlgorithm{hmac.New(sha1.New, writeParameters.clientMAC)}
	writeMac := hmacAlgorithm{hmac.New(sha1.New, writeParameters.serverMAC)}

	block, err := aes.NewCipher(writeParameters.clientKey)
	if err != nil {
		panic(err)
	}
	readCipher := cipher.NewCBCDecrypter(block, writeParameters.clientIV)

	block, err = aes.NewCipher(writeParameters.serverKey)
	if err != nil {
		panic(err)
	}
	writeCipher := cipher.NewCBCEncrypter(block, writeParameters.serverIV)

	c.pendingRead = encryptionState{
		version:     VersionTLS12,
		cipher:      readCipher,
		mac:         readMac,
		compression: compression,
	}

	c.pendingWrite = encryptionState{
		version:     VersionTLS12,
		cipher:      writeCipher,
		mac:         writeMac,
		compression: compression,
	}
}

func (c *Conn) prepareClientCipherSpec(writeParameters keyingMaterial) {
	//XXX This is all fixed to use TLS_RSA_WITH_AES_128_CBC_SHA
	compression := nullCompressionMethod{}
	readMac := hmacAlgorithm{hmac.New(sha1.New, writeParameters.serverMAC)}
	writeMac := hmacAlgorithm{hmac.New(sha1.New, writeParameters.clientMAC)}

	block, err := aes.NewCipher(writeParameters.clientKey)
	if err != nil {
		panic(err)
	}
	writeCipher := cipher.NewCBCEncrypter(block, writeParameters.clientIV)

	block, err = aes.NewCipher(writeParameters.serverKey)
	if err != nil {
		panic(err)
	}
	readCipher := cipher.NewCBCDecrypter(block, writeParameters.serverIV)

	c.pendingRead = encryptionState{
		version:     VersionTLS12,
		cipher:      readCipher,
		mac:         readMac,
		compression: compression,
	}

	c.pendingWrite = encryptionState{
		version:     VersionTLS12,
		cipher:      writeCipher,
		mac:         writeMac,
		compression: compression,
	}
}

func (c *Conn) establishKeys(masterSecret [48]byte, clientRandom, serverRandom [32]byte) {
	params := securityParameters{
		masterSecret: masterSecret,
		clientRandom: clientRandom,
		serverRandom: serverRandom,

		//XXX This is all fixed to use TLS_RSA_WITH_AES_128_CBC_SHA
		encKeyLength:  16,
		fixedIVLength: 16,
		macKeyLength:  20,
	}

	keys := keysFromMasterSecret(params)
	c.prepareCipherSpec(keys)
}

func (c *Conn) changeWriteCipherSpec() {
	//TODO: wipe pending
	c.write = c.pendingWrite
}

func (c *Conn) changeReadCipherSpec() {
	//TODO: wipe pending
	c.read = c.pendingRead
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
