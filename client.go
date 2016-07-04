package toyls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

const (
	clientFinished = "client finished"
)

type handshakeClient struct {
	tls.Certificate
	serverCertificate     *x509.Certificate
	shouldSendCertificate bool

	clientRandom, serverRandom [32]byte
	preMasterSecret            []byte
	bytes.Buffer
}

func newHandshakeClient() *handshakeClient {
	return &handshakeClient{}
}

func (c *handshakeClient) sendClientHello() ([]byte, error) {
	clientRandom := newRandom(rand.Reader)
	message, err := serializeClientHello(&clientHelloBody{
		clientVersion: VersionTLS12,
		random:        clientRandom,
		sessionID:     nil,
		cipherSuites: []cipherSuite{
			cipherSuite{0x00, 0x2f}, // TLS_RSA_WITH_AES_128_CBC_SHA
		},
		compressionMethods: []uint8{0x00}, //No compression
	})

	if err != nil {
		return nil, err
	}

	serializeRandom(c.clientRandom[:], &clientRandom)
	c.Write(message)

	return serializeHandshakeMessage(&handshakeMessage{
		clientHelloType, message,
	}), nil
}

func (c *handshakeClient) receiveServerHello(message []byte) error {
	serverHello, err := deserializeServerHello(message)
	if err != nil {
		return err
	}

	serializeRandom(c.serverRandom[:], &serverHello.random)
	c.Write(message)

	return nil
}

func (c *handshakeClient) receiveCertificate(cert []byte) error {
	certMsg, err := deserializeCertificate(cert)
	if err != nil {
		return err
	}

	//XXX We get only the first certificate
	c.serverCertificate, err = x509.ParseCertificate(certMsg.certificateList[0])
	if err != nil {
		return err
	}

	pubKey := c.serverCertificate.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
		break
	default:
		return fmt.Errorf("tls: unsupported type of public key: %T", pubKey)
	}

	c.Write(cert)
	return nil
}

func (c *handshakeClient) receiveServerKeyExchange(message []byte) {
	//TODO
	c.Write(message)
}

func (c *handshakeClient) receiveCertificateRequest(cert []byte) {
	//Should save the certificateRequest, and only send the message after
	//receiving a helloDone
	c.shouldSendCertificate = true
	c.Write(cert)
}

func (c *handshakeClient) receiveServerHelloDone(done []byte) ([][]byte, error) {
	certificateMsg, err := c.sendCertificate()
	if err != nil {
		return nil, err
	}

	c.Write(done)

	clientKeyExchange, err := c.sendClientKeyExchange()
	toSend := zip(certificateMsg, clientKeyExchange)
	for _, s := range toSend {
		c.Write(s)
	}

	return toSend, err
}

func (c *handshakeClient) sendCertificate() ([]byte, error) {
	if !c.shouldSendCertificate {
		return nil, nil
	}

	return sendCertificate(c.Certificate, c)
}

func (c *handshakeClient) sendClientKeyExchange() ([]byte, error) {
	preMasterSecret, err := generatePreMasterSecret(rand.Reader)
	if err != nil {
		return nil, err
	}

	c.preMasterSecret, err = serializePreMasterSecret(preMasterSecret)
	if err != nil {
		return nil, err
	}

	pub := c.serverCertificate.PublicKey.(*rsa.PublicKey)
	encPreMasterSecret, err := encryptPreMasterSecret(c.preMasterSecret, pub)
	if err != nil {
		return nil, err
	}

	message, err := serializeEncryptedPreMasterSecret(encPreMasterSecret)
	if err != nil {
		return nil, err
	}

	c.Write(message)
	return serializeHandshakeMessage(&handshakeMessage{
		clientKeyExchangeType, message,
	}), nil
}

func (c *handshakeClient) sendCertificateVerify() ([]byte, error) {
	//I guess we won't send this. We are not supporting client certificate at this moment
	//TODO Sign all previous messages with the client's certificate.
	return nil, nil
}

func (c *handshakeClient) sendFinished() ([]byte, error) {
	masterSecret := computeMasterSecret(c.preMasterSecret[:], c.clientRandom[:], c.serverRandom[:])
	verifyData, err := generateVerifyData(masterSecret[:], clientFinished, &c.Buffer)
	if err != nil {
		return nil, err
	}

	return serializeHandshakeMessage(&handshakeMessage{
		finishedType, verifyData,
	}), nil
}

/// Serialization

func deserializeClientHello(h []byte) (*clientHelloBody, error) {
	var err error
	hello := &clientHelloBody{}

	hello.clientVersion, h = extractProtocolVersion(h)
	hello.random, h = extractRandom(h)
	hello.sessionID, h = extractSessionID(h)
	if hello.cipherSuites, h, err = extractCipherSuites(h); err != nil {
		return &clientHelloBody{}, err
	}

	if hello.compressionMethods, _, err = extractCompressionMethods(h); err != nil {
		return &clientHelloBody{}, err
	}

	return hello, nil
}

func serializeClientHello(h *clientHelloBody) ([]byte, error) {
	cipherSuitesLen := len(h.cipherSuites) * cipherSuiteLen
	compressionMethodsLen := len(h.compressionMethods)
	sessionIDLen := len(h.sessionID)
	vectorSizesLen := 4
	capacity := protocolVersionLen + randomLen + cipherSuitesLen + compressionMethodsLen + sessionIDLen + vectorSizesLen

	hello := make([]byte, 0, capacity)
	hello = append(hello, h.clientVersion.major, h.clientVersion.minor)

	gmtUnixTime := writeBytesFromUint32(h.random.gmtUnixTime)
	hello = append(hello, gmtUnixTime[:]...)
	hello = append(hello, h.random.randomBytes[:]...)

	hello = append(hello, byte(sessionIDLen))
	hello = append(hello, h.sessionID...)

	//XXX check size
	ciphersLen := writeBytesFromUint16(uint16(cipherSuitesLen))
	hello = append(hello, ciphersLen[:]...)
	for _, c := range h.cipherSuites {
		hello = append(hello, c[:]...)
	}

	//XXX check size
	hello = append(hello, uint8(compressionMethodsLen))
	hello = append(hello, h.compressionMethods...)

	return hello, nil
}

// See 7.4.1.  Hello Messages
func beginSession() *session {
	//TODO
	//record layer's connection state encryption, hash, and
	//   compression algorithms are initialized to null

	return nil
}
