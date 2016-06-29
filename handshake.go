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

//This will always be EncryptedPreMasterSecret in our case (RSA key-exchange)
type clientKeyExchangeBody struct{}

// See page 58 if you want to play with different attacks on this
// This is where the protocol starts to show all its problems with interoperability
// with stupid clients.
type preMasterSecret struct {
	//This is in response to the version rollback attack
	//It is interesting to note that after agreeing on a version, all the subsequent
	//messages just assume both sides will behave and use the version they have agreed
	//upon. If you compare this to OTR, every message after the version agreement
	//contains the version.
	clientVersion protocolVersion
	random        [46]byte
}

//XXX This can be postponed until we actually start running the handshake.
//For now, we are only doing serialization/deserialization.
type encryptedPreMasterSecretBody struct {
	// This is encrypted using the public key from the server's certificate
	// In our case (we're going to start with RSA):
	// RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
	// defined in [PKCS1].
	preMasterSecret []byte // Size is <0..2^16-1>
}

type finishedBody struct {
	//Size: verify_data_length OR 12 (if not specified by the cipher suite)
	verify_data []byte
}
