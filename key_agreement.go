package toyls

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"math/big"
)

// ecdheRSAKeyAgreement implements a TLS key agreement where the server
// generates a ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// either be ECDSA or RSA.
type ecdheKeyAgreement struct {
	privateKey []byte
	curve      elliptic.Curve
	x, y       *big.Int
}

var (
	signatureRSAFunc byte   = 1
	sha1Func         byte   = 2
	CurveP256        uint16 = 23
)

func (ka *ecdheKeyAgreement) generateServerKeyExchange(cert tls.Certificate, clientRandom, serverRandom [32]byte) *serverKeyExchangeBody {
	ka.curve = elliptic.P256()
	ka.privateKey, ka.x, ka.y, _ = elliptic.GenerateKey(ka.curve, rand.Reader)
	ecdhePublic := elliptic.Marshal(ka.curve, ka.x, ka.y)
	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(CurveP256 >> 8)
	serverECDHParams[2] = byte(CurveP256)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	h := sha1.New()
	h.Write(clientRandom[:])
	h.Write(serverRandom[:])
	h.Write(serverECDHParams)
	digest := h.Sum(nil)

	sig, _ := cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest, crypto.SHA1)

	return &serverKeyExchangeBody{
		params:        serverECDHParams,
		hashFunc:      sha1Func,
		signatureFunc: signatureRSAFunc,
		signature:     sig,
	}
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(ciphertext []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(ka.curve, ciphertext[1:])
	if x == nil {
		return nil, errors.New("wrong ciphertext")
	}
	if !ka.curve.IsOnCurve(x, y) {
		return nil, errors.New("not on curve")
	}
	x, _ = ka.curve.ScalarMult(x, y, ka.privateKey)
	preMasterSecret := make([]byte, (ka.curve.Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	return preMasterSecret, nil
}
