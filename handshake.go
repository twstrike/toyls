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

type helloRequestBody struct{}
type clientHelloBody struct{}
type serverHelloBody struct{}
type certificateBody struct{}
type serverKeyExchangeBody struct{}
type certificateRequestBody struct{}
type serverHelloDoneBody struct{}
type certificateVerifyBody struct{}
type clientKeyExchangeBody struct{}
type finishedBody struct{}
