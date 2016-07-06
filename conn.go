package toyls

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const recordHeaderLen = 5

type Conn struct {
	state  connectionState
	params securityParameters
	wp     writeParams

	chunkSize uint16

	*handshakeServer
	*handshakeClient

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
		handshakeServer: &handshakeServer{},
		handshakeClient: &handshakeClient{},

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

func (c *Conn) send(contentType ContentType, version protocolVersion, content []byte) ([]byte, error) {
	var err error
	ret := []byte{}
	var plainText TLSPlaintext
	for len(content) > 0 {
		plainText, content, err = c.fragment(contentType, version, content)
		if err != nil {
			return nil, err
		}

		compressed, err := c.compress(plainText)
		if err != nil {
			return nil, err
		}

		cipherText, err := c.macAndEncrypt(compressed)
		if err != nil {
			return nil, err
		}

		seq := binary.BigEndian.Uint64(c.state.writeSequenceNumber[:]) //TODO: alert for renegotiation
		binary.BigEndian.PutUint64(c.state.writeSequenceNumber[:], seq+1)
		ret = append(ret, cipherText.serialize()...)
	}

	return ret, nil
}

func (c *Conn) receive(in io.Reader) chan []byte {
	toSend := make(chan []byte, 4)
	go func() {
		for {
			cipherText, err := c.handleFragment(in)
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
			c.handlePlainText(plainText, toSend)
			seq := binary.BigEndian.Uint64(c.state.readSequenceNumber[:]) //TODO: alert for renegotiation
			binary.BigEndian.PutUint64(c.state.readSequenceNumber[:], seq+1)
		}
	}()

	return toSend
}

func (c *Conn) hello() ([]byte, error) {
	h, err := c.sendClientHello()
	if err != nil {
		//TODO send alert message
		panic("error")
	}

	//After this, receiving anything but a serverHello is a fatal
	//error

	return c.sendHandshake(h)
}

func (c *Conn) sendHandshake(h []byte) ([]byte, error) {
	return c.send(HANDSHAKE, VersionTLS12, h)
}

func (c *Conn) sendChangeCipher() ([]byte, error) {
	return c.send(CHANGE_CIPHER_SPEC, VersionTLS12, []byte{1})
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

func (c *Conn) handlePlainText(plaintext TLSPlaintext, toSend chan []byte) {
	//Should we check the version?

	switch plaintext.contentType {
	default:
		panic("unsupported content type")
	case HANDSHAKE:
		err := c.receiveHandshakeMessage(plaintext.fragment, toSend)
		if err != nil {
			//send alert message?
			return
		}

		return
	case CHANGE_CIPHER_SPEC:
		//TODO: should store that it received the changeCipher
		//and react to it
	case ALERT:
		panic("Receiveing ALERT")
	}

	return
}

func (c *Conn) receiveHandshakeMessage(msg []byte, toSend chan []byte) error {
	h := deserializeHandshakeMessage(msg)

	switch h.msgType {
	case helloRequestType:
		m, err := c.sendClientHello()
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m
	case clientHelloType:
		m, err := c.receiveClientHello(h.message)
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m

		//TODO: check if the key exchange uses a certificate.
		m, err = c.handshakeServer.sendCertificate()
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m

		//IF we need a Server Key Exchange Message,
		//send it NOW.

		//IF we need a Certificate Request,
		//send it NOW.

		//MUST always finishes with a serverHelloDone
		m, err = c.sendServerHelloDone()
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m

	case serverHelloType:
		err := c.receiveServerHello(h.message)
		if err != nil {
			return err
		}

	case certificateType:
		err := c.receiveCertificate(h.message)
		if err != nil {
			return err
		}

	case serverKeyExchangeType:
		//Not yet
	case certificateRequestType:
		//Not yet
	case serverHelloDoneType:
		//Send Certificate if have to
		//Send ClientKeyExchange if have to
		//Send CertificateVerify if have to

		m, err := c.sendClientKeyExchange()
		if err != nil {
			return err
		}
		toSend <- m

		m, err = c.sendChangeCipher()
		if err != nil {
			return err
		}

		toSend <- m

		m, err = c.handshakeClient.sendFinished()
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m
	case certificateVerifyType:
		//Not yet
	case clientKeyExchangeType:
		//Not yet
	case finishedType:
		//TODO: Chek if it has received a changeCipher. How will we know if the received
		//changeCipher is from this handshake or not?

		m, err := c.sendChangeCipher()
		if err != nil {
			return err
		}

		toSend <- m

		m, err = c.handshakeClient.sendFinished()
		if err != nil {
			return err
		}

		m, err = c.sendHandshake(m)
		if err != nil {
			return err
		}

		toSend <- m
	}

	return nil
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
