package toyls

import (
	"crypto/rand"
	"crypto/tls"
)

type handshakeServer struct {
	// Certificates contains one or more certificate chains
	// to present to the other side of the connection.
	// Server configurations must include at least one certificate
	// or else set GetCertificate.
	//XXX Why does tls.Config has an []Certificate?
	tls.Certificate
}

func newHandshakeServer() *handshakeServer {
	return &handshakeServer{}
}

func (s *handshakeServer) receiveClientHello(m []byte) ([]byte, error) {
	_, err := deserializeClientHello(m)
	if err != nil {
		return nil, err
	}

	//TODO: check all things and return error if we cant agree

	serverHello := &serverHelloBody{
		serverVersion:     VersionTLS12, //If supported by the client
		random:            newRandom(rand.Reader),
		sessionID:         nil,                     // we dont support session resume
		cipherSuite:       cipherSuite{0x00, 0x2f}, //If supported by the client
		compressionMethod: 0x00,                    //Is supported by the client
	}

	message, err := serializeServerHello(serverHello)
	if err != nil {
		return nil, err
	}

	return serializeHandshakeMessage(&handshakeMessage{
		serverHelloType, message,
	}), nil
}

func (s *handshakeServer) sendCertificate() ([]byte, error) {
	//Should have checked if the agreed-upon key exchange method uses
	//certificates for authentication. For now, our method always supports.
	serverCertificate := &certificateBody{
		//XXX Should we deep-copy?
		certificateList: s.Certificate.Certificate,
	}

	message, err := serializeCertificate(serverCertificate)
	if err != nil {
		return nil, err
	}

	return serializeHandshakeMessage(&handshakeMessage{
		certificateType, message,
	}), nil
}

func (s *handshakeServer) sendServerKeyExchange() ([]byte, error) {
	//Our key exchange method does not send this message. Easy ;)
	return nil, nil
}

func (s *handshakeServer) sendCertificateRequest() ([]byte, error) {
	//Not supported, for now. Easy ;)
	return nil, nil
}

func (s *handshakeServer) sendServerHelloDone() ([]byte, error) {
	return serializeHandshakeMessage(&handshakeMessage{
		serverHelloDoneType, nil,
	}), nil
}

func deserializeServerHello(h []byte) (*serverHelloBody, error) {
	hello := &serverHelloBody{}

	hello.serverVersion, h = extractProtocolVersion(h)
	hello.random, h = extractRandom(h)
	hello.sessionID, h = extractSessionID(h)
	h = extractCipherSuite(hello.cipherSuite[:], h)
	hello.compressionMethod = h[0]

	//XXX It never fails
	return hello, nil
}

func serializeServerHello(h *serverHelloBody) ([]byte, error) {
	compressionMethodLen := 1
	sessionIDLen := len(h.sessionID)
	vectorSizesLen := 4
	capacity := protocolVersionLen + randomLen + cipherSuiteLen + compressionMethodLen + sessionIDLen + vectorSizesLen

	hello := make([]byte, 0, capacity)
	hello = append(hello, h.serverVersion.major, h.serverVersion.minor)

	gmtUnixTime := writeBytesFromUint32(h.random.gmtUnixTime)
	hello = append(hello, gmtUnixTime[:]...)
	hello = append(hello, h.random.randomBytes[:]...)

	hello = append(hello, byte(sessionIDLen))
	hello = append(hello, h.sessionID...)

	hello = append(hello, h.cipherSuite[:]...)
	hello = append(hello, h.compressionMethod)

	return hello, nil
}

func deserializeCertificate(c []byte) (*certificateBody, error) {
	certificateBody := &certificateBody{
		certificateList: make([][]byte, 0, 10),
	}

	certListLen, c := extractUint24(c)
	certLen := uint32(0)
	vectorLenSize := uint32(3)

	for i := uint32(0); i < certListLen; i += certLen + vectorLenSize {
		certLen, c = extractUint24(c)
		certificate := make([]byte, certLen)
		copy(certificate[:], c[:certLen])
		c = c[certLen:]

		certificateBody.certificateList = append(certificateBody.certificateList,
			certificate)
	}

	return certificateBody, nil
}

func serializeCertificate(c *certificateBody) ([]byte, error) {
	certListBody := make([]byte, 0, 0xffffff) // 2^24-1 is maximim length
	for _, ci := range c.certificateList {
		//XXX check len(ci). It should be less than 0xFFFFFF
		certificateLen := writeBytesFromUint24(uint32(len(ci)))
		certListBody = append(certListBody, certificateLen[:]...)
		certListBody = append(certListBody, ci...)
	}

	certificateListLen := writeBytesFromUint24(uint32(len(certListBody)))
	cert := append(certificateListLen[:], certListBody...)

	return cert, nil
}
