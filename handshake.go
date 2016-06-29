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

type cipherSuite [2]uint8

type random struct {
	gmtUnixTime uint32
	randomBytes [28]byte
}

type helloRequestBody struct{}

type clientHelloBody struct {
	clientVersion protocolVersion
	random
	sessionID          []byte        //Min: 0, Max: 32
	cipherSuites       []cipherSuite //Min: 2, Max: 2^16-2
	compressionMethods []uint8       //Min: 1, Max: 2^8-1
	//extensions
}

type serverHelloBody struct {
	serverVersion protocolVersion
	random
	sessionID []byte //Min: 0, Max: 32
	cipherSuite
	compressionMethod uint8
	//extensions
}

type certificateBody struct {
	certificateList [][]byte
}

//XXX This is too iffy, depending on the KeyExchangeAlgorithm.
//We should probably use a different body for each key exchange algo, or
//implement only one.
//XXX We are going to implement only RSA key exchange, so this is not necessary (for now)
//See: "7.4.3.  Server Key Exchange Message" to understand why we dont neeed this now.
type serverKeyExchangeBody struct{}

//XXX We believe this is not mandatory for TLS_RSA_WITH_AES_128_CBC_SHA
type certificateRequestBody struct{}

//This is empty. No need to serialize/deserialize.
//XXX Remove-me
type serverHelloDoneBody struct{}

//XXX Not necessary until our server sends certificateRequest
type certificateVerifyBody struct{}

type clientKeyExchangeBody struct{}
type finishedBody struct{}
