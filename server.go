package toyls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
)

type handshakeServer struct {
	// Certificates contains one or more certificate chains
	// to present to the other side of the connection.
	// Server configurations must include at least one certificate
	// or else set GetCertificate.
	//XXX Why does tls.Config has an []Certificate?
	tls.Certificate

	clientRandom, serverRandom [32]byte
	preMasterSecret            []byte
	bytes.Buffer
}

func newHandshakeServer() *handshakeServer {
	return &handshakeServer{}
}

func (s *handshakeServer) receiveClientHello(m []byte) ([]byte, error) {
	s.Write(m)

	clientHello, err := deserializeClientHello(m)
	if err != nil {
		return nil, err
	}

	serializeRandom(s.clientRandom[:], &clientHello.random)

	return s.agree(clientHello)
}

func (s *handshakeServer) agree(h *clientHelloBody) ([]byte, error) {
	version, err := s.checkSupportedVersion(h.clientVersion)
	if err != nil {
		return nil, err
	}

	cipherSuite, err := s.checkSupportedCipherSuites(h.cipherSuites)
	if err != nil {
		return nil, err
	}

	compressionMethod, err := s.checkSupportedCompressionMethods(h.compressionMethods)
	if err != nil {
		return nil, err
	}

	return s.sendServerHello(version, cipherSuite, compressionMethod)
}

func (s *handshakeServer) checkSupportedVersion(v protocolVersion) (protocolVersion, error) {
	if v != VersionTLS12 {
		return v, errors.New("unsupported version")
	}

	return v, nil
}

func (s *handshakeServer) checkSupportedCipherSuites(suites []cipherSuite) (cipherSuite, error) {
	supported := cipherSuite{0x00, 0x2f}

	for _, cs := range suites {
		if cs == supported {
			return cs, nil
		}
	}

	return cipherSuite{}, errors.New("unsupported cipher suite")
}

func (s *handshakeServer) checkSupportedCompressionMethods(methods []uint8) (uint8, error) {
	for _, cm := range methods {
		if cm == 0 {
			return cm, nil
		}
	}

	return 0xff, errors.New("unsupported compression method")
}

func (s *handshakeServer) sendServerHello(version protocolVersion, cipherSuite cipherSuite, compressionMethod uint8) ([]byte, error) {
	serverRandom := newRandom(rand.Reader)
	serverHello := &serverHelloBody{
		serverVersion:     version,
		random:            serverRandom,
		sessionID:         nil, // we dont support session resume
		cipherSuite:       cipherSuite,
		compressionMethod: compressionMethod,
	}

	message, err := serializeServerHello(serverHello)
	if err != nil {
		return nil, err
	}

	serializeRandom(s.serverRandom[:], &serverRandom)
	s.Write(message)

	return serializeHandshakeMessage(&handshakeMessage{
		serverHelloType, message,
	}), nil
}

func (s *handshakeServer) sendCertificate() ([]byte, error) {
	//Should have checked if the agreed-upon key exchange method uses
	//certificates for authentication. For now, our method always supports.
	return sendCertificate(s.Certificate, s)
}

func (s *handshakeServer) sendServerKeyExchange() ([]byte, error) {
	//Our key exchange method does not send this message. Easy ;)
	//s.Write(m)
	return nil, nil
}

func (s *handshakeServer) sendCertificateRequest() ([]byte, error) {
	//Not supported, for now. Easy ;)
	//s.Write(m)
	return nil, nil
}

func (s *handshakeServer) sendServerHelloDone() ([]byte, error) {
	return serializeHandshakeMessage(&handshakeMessage{
		serverHelloDoneType, nil,
	}), nil
}

// func receiveCertificate()
// func receiveClientKeyExchange()
// func receiveCertificateVerify()

func (s *handshakeServer) receiveFinished(m []byte) error {
	s.Write(m)

	//TODO
	return nil
}

func (s *handshakeServer) sendFinished() ([]byte, error) {
	//XXX This is exactly the same as the client. Should it be?
	//TODO: Store preMasterSecret, clientRandom, serverRandom
	masterSecret := computeMasterSecret(s.preMasterSecret[:], s.clientRandom[:], s.serverRandom[:])
	verifyData, err := generateVerifyData(masterSecret[:], clientFinished, &s.Buffer)
	if err != nil {
		return nil, err
	}

	return serializeHandshakeMessage(&handshakeMessage{
		finishedType, verifyData,
	}), nil
}

// Serialize

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
