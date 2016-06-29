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
	hello := &clientHelloBody{}
	hello.clientVersion, h = extractProtocolVersion(h)
	hello.random.gmtUnixTime, h = extractUint32(h)
	copy(hello.random.randomBytes[:], h[:28])

	sessionLen := int(h[28])
	hello.sessionID = make([]byte, sessionLen)
	copy(hello.sessionID, h[29:29+sessionLen])

	var err error
	ciphersStart := 29 + sessionLen
	if hello.cipherSuites, h, err = extractCipherSuites(h[ciphersStart:]); err != nil {
		return &clientHelloBody{}, err
	}

	compressions := int(h[0])
	hello.compressionMethods = make([]byte, compressions)
	copy(hello.compressionMethods[:], h[1:1+compressions])

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
