package toyls

import (
	"errors"
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

	hello.clientVersion.major = h[0]
	hello.clientVersion.minor = h[1]

	hello.random.gmtUnixTime, h = extractUint32(h[2:])
	copy(hello.random.randomBytes[:], h[:28])

	sessionLen := int(h[28])
	hello.sessionID = make([]byte, sessionLen)
	copy(hello.sessionID, h[29:29+sessionLen])

	ciphersStart := 29 + sessionLen
	ciphers, h := extractUint16(h[ciphersStart:])
	if ciphers < 2 || ciphers > 2^16-1 {
		return &clientHelloBody{}, errors.New("The cipher suite list should contain <2..2^16-2> elements.")
		
	}
	hello.cipherSuites = make([]cipherSuite, ciphers/2)
	for i := 0; i < int(ciphers)/2; i++ {
		s := &hello.cipherSuites[i]
		copy(s[:], h[i*2:i*2+2])
	}

	compressionStart := int(ciphers)
	compressions := int(h[compressionStart])
	hello.compressionMethods = make([]byte, compressions)
	copy(hello.compressionMethods[:], h[compressionStart+1:compressionStart+1+compressions])

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
