package toyls

import (
	"io"
	"time"
)

type handshakeClient struct{}

func newHandshakeClient() *handshakeClient {
	return &handshakeClient{}
}

func (c *handshakeClient) sendClientHello() []byte {
	return nil
}

func deserializeClientHello(h []byte) (*clientHelloBody, error) {
	var err error
	hello := &clientHelloBody{}

	hello.clientVersion, h = extractProtocolVersion(h)
	hello.random, h = extractRandom(h)
	hello.sessionID, h = extractSessionID(h)
	if hello.cipherSuites, h, err = extractCipherSuites(h); err != nil {
		return &clientHelloBody{}, err
	}

	if hello.compressionMethods, _, err = extractCompressionMethods(h); err != nil {
		return &clientHelloBody{}, err
	}

	return hello, nil
}

func serializeClientHello(h *clientHelloBody) ([]byte, error) {
	ciphers := len(h.cipherSuites)
	compressions := len(h.compressionMethods)
	sessionLen := len(h.sessionID)
	capacity := 34 + ciphers * 2 + compressions + 4 + sessionLen
	hello := make([]byte, 2, capacity)

	hello[0] = h.clientVersion.major
	hello[1] = h.clientVersion.minor

	gmtUnixTime := writeBytesFromUint32(h.random.gmtUnixTime)
	hello = append(hello, gmtUnixTime[:]...)
	hello = append(hello, h.random.randomBytes[:]...)

	hello = append(hello, byte(sessionLen))
	hello = append(hello, h.sessionID...)

	ciphersLen := writeBytesFromUint16(uint16(ciphers * 2))
	hello = append(hello, ciphersLen[:]...)
	for _, c :=  range h.cipherSuites {
		hello = append(hello, c[:]...)
	}

	hello = append(hello, uint8(compressions))
	hello = append(hello, h.compressionMethods...)

	return hello, nil
}

// See 7.4.1.  Hello Messages
func beginSession() *session {
	//TODO
	//record layer's connection state encryption, hash, and
	//   compression algorithms are initialized to null

	return nil
}

//XXX I guess this should be different for client and server
func receiveHandshakeMessage(m interface{}) interface{} {
	//TODO
	switch m.(type) {
	default:
		//unexpected
	case helloRequestBody:
		// See: 7.4.1.1.  Hello Request
		//Ignore if the client is currently negotiating a session
		//MAY be ignored if it does not wish to renegotiate a session, or the
		//      client may, if it wishes, respond with a no_renegotiation alert.
		//Send ClientHello
		return &clientHelloBody{}
	case clientHelloBody:
		// See: 7.4.1.3.  Server Hello
		//Send ServerHello
		return &serverHelloBody{}

		//If the agreed-upon key exchange method uses certificates for authentication
		//MUST send this immediatelly
		return &certificateBody{}
	case certificateBody:
		// See: 7.4.3.  Server Key Exchange Message
		//
		return &serverKeyExchangeBody{}
	}

	return nil
}

func newClientHello() *handshakeMessage {
	return &handshakeMessage{
		msgType: clientHelloType,
		length:  0,
		body:    &clientHelloBody{},
	}
}

func newRandom(r io.Reader) random {
	t := time.Now().Unix()
	if t < 0 {
		panic("Wrong time")
	}

	rand := random{
		gmtUnixTime: uint32(t),
	}

	io.ReadFull(r, rand.randomBytes[:])

	return rand
}
