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
	serverFinished = "server finished"
)

type handshakeClient struct {
	serverCertificate     *x509.Certificate
	shouldSendCertificate bool

	*tls.Config
	tls.Certificate //XXX replace by Config.Certificates[0] ??

	clientRandom, serverRandom [32]byte
	preMasterSecret            []byte
	masterSecret               [48]byte

	bytes.Buffer
	recordProtocol
}

func newHandshakeClient() *handshakeClient {
	return &handshakeClient{Config: &tls.Config{
		InsecureSkipVerify: true,
	}}
}

func (c *handshakeClient) receiveHelloRequest(r []byte) ([]byte, error) {
	return c.sendClientHello()
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

	return nil
}

func parseCertificateList(certList [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(certList))
	for _, asn1Data := range certList {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func (c *handshakeClient) verifyCertificateChain(chain []*x509.Certificate) error {
	if c.Config.InsecureSkipVerify {
		return nil
	}

	opts := x509.VerifyOptions{
		Roots: c.Config.RootCAs,
		//CurrentTime:   c.Config.Time(),
		DNSName:       c.Config.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range chain {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, err := chain[0].Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

func (c *handshakeClient) receiveCertificate(cert []byte) error {
	certMsg, err := deserializeCertificate(cert)
	if err != nil {
		return err
	}

	certs, err := parseCertificateList(certMsg.certificateList)
	if err != nil {
		c.sendFatalAlert(badCertificate)
		return err
	}

	//XXX We get only the first certificate
	c.serverCertificate = certs[0]

	err = c.verifyCertificateChain(certs)
	if err != nil {
		c.sendFatalAlert(badCertificate)
		return err
	}

	pubKey := c.serverCertificate.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
		break
	default:
		return fmt.Errorf("tls: unsupported type of public key: %T", pubKey)
	}

	return nil
}

func (c *handshakeClient) receiveServerKeyExchange(message []byte) {
	//TODO
}

func (c *handshakeClient) receiveCertificateRequest(cert []byte) {
	//Should save the certificateRequest, and only send the message after
	//receiving a helloDone
	c.shouldSendCertificate = true
}

func (c *handshakeClient) receiveServerHelloDone(done []byte) ([][]byte, error) {
	certificateMsg := c.sendCertificate()

	clientKeyExchange, err := c.sendClientKeyExchange()
	if err != nil {
		return nil, err
	}

	certificateVerify, err := c.sendCertificateVerify()

	return zip(certificateMsg, clientKeyExchange, certificateVerify), err
}

func (c *handshakeClient) sendCertificate() []byte {
	if !c.shouldSendCertificate {
		return nil
	}

	return sendCertificate(c.Certificate)
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
	verifyData, err := generateVerifyData(c.masterSecret[:], clientFinished, &c.Buffer)
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

//Client initiates the handshake
func (c *handshakeClient) doHandshake() error {
	//XXX Where should we handle the helloRequest?
	m, err := c.sendClientHello()
	if err != nil {
		return err
	}

	//fmt.Println("client (clientHello) ->")
	c.Write(m)
	err = c.writeRecord(HANDSHAKE, m)
	if err != nil {
		return err
	}

	r, err := c.readRecord(HANDSHAKE)
	if err != nil {
		return err
	}

	h := deserializeHandshakeMessage(r)
	c.Write(r)
	err = c.receiveServerHello(h.message)
	if err != nil {
		return err
	}

	r, err = c.readRecord(HANDSHAKE)
	if err != nil {
		return err
	}

	h = deserializeHandshakeMessage(r)
	c.Write(r)

	err = c.receiveCertificate(h.message)
	if err != nil {
		return err
	}

	r, err = c.readRecord(HANDSHAKE)
	if err != nil {
		return err
	}

	h = deserializeHandshakeMessage(r)
	c.Write(r)
	toSend, err := c.receiveServerHelloDone(h.message)
	if err != nil {
		return err
	}

	//fmt.Println("client (clientKeyExchange) ->")
	c.Write(toSend[0])
	err = c.writeRecord(HANDSHAKE, toSend[0])
	if err != nil {
		return err
	}

	c.masterSecret = computeMasterSecret(c.preMasterSecret[:], c.clientRandom[:], c.serverRandom[:])
	c.recordProtocol.establishKeys(c.masterSecret, c.clientRandom, c.serverRandom)

	//fmt.Println("client (changeCipherSpec) ->")
	err = c.writeRecord(CHANGE_CIPHER_SPEC, []byte{1})
	if err != nil {
		return err
	}

	//Immediately after sending [ChangeCipherSpec], the sender MUST instruct the
	//record layer to make the write pending state the write active state.
	c.recordProtocol.changeWriteCipherSpec()

	m, err = c.sendFinished()
	if err != nil {
		return err
	}

	//fmt.Println("client (finished) ->")
	err = c.writeRecord(HANDSHAKE, m)
	if err != nil {
		return err
	}

	r, err = c.readRecord(CHANGE_CIPHER_SPEC)
	if err != nil {
		return err
	}

	//Reception of [ChangeCipherSpec] causes the receiver to instruct the record
	//layer to immediately copy the read pending state into the read current state.
	c.recordProtocol.changeReadCipherSpec()

	r, err = c.readRecord(HANDSHAKE)
	if err != nil {
		return err
	}

	h = deserializeHandshakeMessage(r)
	//XXX Check if finished matches what we expected

	return nil
}

func (c *handshakeClient) setRecordProtocol(r recordProtocol) {
	c.recordProtocol = r
}

func (c *handshakeClient) sendFatalAlert(d alertDescription) {
	alert := &alertMessage{fatal, d}
	c.recordProtocol.writeRecord(ALERT, alert.marshall())
}
