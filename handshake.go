package toyls

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

type handshakeMessage struct {
	msgType handshakeType

	//This should be uint24, and we should keep track of overflows
	//Is this always 3 + len(body)?
	length uint32

	// It depends on msgType
	// should it be a []byte?
	body interface{}
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
