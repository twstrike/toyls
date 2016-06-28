package toytls

// See 5246, section 7.  The TLS Handshaking Protocols

// The Handshake Protocol is responsible for negotiating a session
type session struct {
	sessionID, peerCertificate, compressionMethod, cipherSpec interface{}
	masterSecret                                              [48]byte
	isResumable                                               bool
}

type handshakeType uint8

const (
	helloRequestType       handshakeType = 0
	clientHelloType                      = 1
	serverHelloType                      = 2
	certificateType                      = 11
	serverKeyExchangeType                = 12
	certificateRequestType               = 13
	serverHelloDoneType                  = 14
	certificateVerifyType                = 15
	clientKeyExchangeType                = 16
	finishedType                         = 20
)

type handshake struct {
	msgType handshakeType
	length  uint32      //This should be uint24, and we should keep track of overflows
	body    interface{} // depends on msgType
}

type protocolVersion struct {
	major, minor uint8
}

type cypherSuite [2]uint8

type random struct {
	gmtUnixTime uint32
	randomBytes [28]byte
}

type helloRequestBody struct{}

type clientHelloBody struct {
	clientVersion protocolVersion
	random
	sessionID          []byte        //Min: 0, Max: 32
	cipherSuites       []cypherSuite //Min: 2, Max: 2^16-2
	compressionMethods []uint8       //Min: 1, Max: 2^8-1
	//extensions
}

type serverHelloBody struct {
	serverVersion protocolVersion
	random
	sessionID []byte //Min: 0, Max: 32
	cypherSuite
	compressionMethod uint8
	//extensions
}

type certificateBody struct {
	certificateList [][]byte
}

//XXX This is too iffy, depending on the KeyExchangeAlgorithm.
//We should probably use a different body for each key exchange algo, or
//implement only one.
type serverKeyExchangeBody struct{}

type certificateRequestBody struct{}
type serverHelloDoneBody struct{}
type certificateVerifyBody struct{}
type clientKeyExchangeBody struct{}
type finishedBody struct{}

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
