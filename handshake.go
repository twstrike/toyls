package toyls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"io/ioutil"
	"time"
)

type handshaker interface {
	doHandshake()
	setRecordProtocol(recordProtocol)
}

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
	clientHelloType        handshakeType = 1
	serverHelloType        handshakeType = 2
	certificateType        handshakeType = 11
	serverKeyExchangeType  handshakeType = 12
	certificateRequestType handshakeType = 13
	serverHelloDoneType    handshakeType = 14
	certificateVerifyType  handshakeType = 15
	clientKeyExchangeType  handshakeType = 16
	finishedType           handshakeType = 20
)

type handshakeMessage struct {
	msgType handshakeType
	message []byte
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

func serializeHandshakeMessage(m *handshakeMessage) []byte {
	msgLen := writeBytesFromUint24(uint32(len(m.message)))

	dst := make([]byte, 0, len(m.message)+4)
	dst = append(dst, byte(m.msgType))
	dst = append(dst, msgLen[:]...)
	return append(dst, m.message...)
}

func deserializeHandshakeMessage(m []byte) *handshakeMessage {
	msgType := m[0]
	messageLen, m := extractUint24(m[1:])
	message := make([]byte, messageLen)
	copy(message, m[:messageLen])

	return &handshakeMessage{
		msgType: handshakeType(msgType),
		message: message,
	}
}

//TODO: remove this error
func sendCertificate(cert tls.Certificate, w io.Writer) ([]byte, error) {
	//XXX I think this is wrong. It should be a list of certificateChains, maybe.
	body := &certificateBody{
		//XXX Should we deep-copy?
		certificateList: cert.Certificate,
	}

	message, err := serializeCertificate(body)
	if err != nil {
		return nil, err
	}

	w.Write(message)
	return serializeHandshakeMessage(&handshakeMessage{
		certificateType, message,
	}), nil
}

//See: 7.4.7.1.  RSA-Encrypted Premaster Secret Message
func encryptPreMasterSecret(preMasterSecret []byte, pub *rsa.PublicKey) (*encryptedPreMasterSecretBody, error) {
	out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, preMasterSecret)
	if err != nil {
		return nil, err
	}

	return &encryptedPreMasterSecretBody{out}, nil
}
func generatePreMasterSecret(r io.Reader) (*preMasterSecret, error) {
	s := &preMasterSecret{
		clientVersion: VersionTLS12,
	}

	_, err := io.ReadFull(r, s.random[:])
	return s, err
}

func serializePreMasterSecret(s *preMasterSecret) ([]byte, error) {
	dst := make([]byte, 0, 48)
	dst = append(dst, s.clientVersion.major, s.clientVersion.minor)
	return append(dst, s.random[:]...), nil
}

func serializeRandom(dst []byte, r *random) []byte {
	gmtUnixTime := writeBytesFromUint32(r.gmtUnixTime)
	copy(dst, gmtUnixTime[:])
	copy(dst[4:], r.randomBytes[:])

	return dst[32:]
}

func serializeEncryptedPreMasterSecret(s *encryptedPreMasterSecretBody) ([]byte, error) {
	dst := make([]byte, len(s.preMasterSecret))
	copy(dst, s.preMasterSecret)
	return dst, nil
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

//See: 8.1.  Computing the Master Secret
func computeMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) [48]byte {
	out := [48]byte{}

	seed := make([]byte, len(clientRandom)+len(serverRandom))
	copy(seed, clientRandom)
	copy(seed[len(clientRandom):], serverRandom)

	prf(out[:], preMasterSecret, "master secret", seed)
	return out
}

func generateVerifyData(masterSecret []byte, finishedLabel string, handshakeReader io.Reader) ([]byte, error) {
	handshakeMessages, err := ioutil.ReadAll(handshakeReader)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write(handshakeMessages)
	messagesHash := hash.Sum(nil)

	dst := make([]byte, 12)
	prf(dst, masterSecret, finishedLabel, messagesHash)

	return dst, nil
}

func zip(pieces ...[]byte) [][]byte {
	dst := make([][]byte, 0, len(pieces))
	for _, piece := range pieces {
		if piece != nil {
			dst = append(dst, piece)
		}
	}

	return dst
}
