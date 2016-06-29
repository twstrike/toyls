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
	hello.random, h = extractRandom(h)
	hello.sessionID, h = extractSessionID(h)

	var err error
	if hello.cipherSuites, h, err = extractCipherSuites(h); err != nil {
		return &clientHelloBody{}, err
	}

	hello.compressionMethods, _ = extractCompressionMethods(h)

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
