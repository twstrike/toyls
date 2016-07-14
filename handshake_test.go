package toyls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"

	. "gopkg.in/check.v1"
)

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIJAPhQs/r8Ls5uMA0GCSqGSIb3DQEBCwUAMDgxCzAJBgNV
BAYTAkVDMQ4wDAYDVQQIEwVRdWl0bzEZMBcGA1UEChMQVGhvdWdodHdvcmtzIElu
YzAeFw0xNjA3MTQyMjA2MzZaFw0yNjA3MTIyMjA2MzZaMDgxCzAJBgNVBAYTAkVD
MQ4wDAYDVQQIEwVRdWl0bzEZMBcGA1UEChMQVGhvdWdodHdvcmtzIEluYzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMJ2MObKlhVsERwUsvPE5yxSEdSs
bvYPzAKFoYmHNxLRFQFfvZw9NhzqsVI2Ur3XIh5GOdwnOKa8C8xVIFts0jQlwie1
Bj2wx4/32mrL8k7AfJbgI794D6kWK0bMlC+8H0o5NWj1w8DOVH3pm6JOxkIhMDL8
xl1ZWiC5Iw7ZBhCHr3yjp9AadcsUOYDOWIgZV/1BxL4Oam7/AwAoI5YbrWwgw4g+
iPHZxJI7FIUjYcGNht+HuV9Q0jwmkT8zJlOTYoB0tShZw+jgTdb0RETAyW++bCvZ
H1Kbp0tN3Ek8nwQNfCH1AH1MNyTHqNiyZcgTaUm8kyG+BAsL3T6qSUElYxMCAwEA
AaOBmjCBlzAdBgNVHQ4EFgQUr3BnOnAWvHAmztRzyoJm+3HGI48waAYDVR0jBGEw
X4AUr3BnOnAWvHAmztRzyoJm+3HGI4+hPKQ6MDgxCzAJBgNVBAYTAkVDMQ4wDAYD
VQQIEwVRdWl0bzEZMBcGA1UEChMQVGhvdWdodHdvcmtzIEluY4IJAPhQs/r8Ls5u
MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABYBKIkwOdsyP3axrM9y
kWtO67j8qLpsIz3lHsabDK2jW631/FRj3vI4m61FCSMTQd1vwWpSP5JN+k6D560P
qbhrtvHdXMNDC61T34p2l15wddusxQ7DTFJdPh4sTj6B1BU6GJw3jjv17jPVpuhw
6+LaQfI6VStfMKMbtqZJ4ai0Qbm9GbtZRX2vPhlGayQxCT39nqud6tmbgd5Dspw2
iYCewvjVHhu6POrZ72+3iUzIBH34iH7VwEu+8106uuJ1l/AErfUKyDQdH+++rmzN
uyfx4Si6H3BT1Fx/KU7nyPoVS3C8+eyDyE80GUb2wWHp6Wm5wiwgM/uiiy7RvXvB
BiY=
-----END CERTIFICATE-----`

var rsaKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwnYw5sqWFWwRHBSy88TnLFIR1Kxu9g/MAoWhiYc3EtEVAV+9
nD02HOqxUjZSvdciHkY53Cc4prwLzFUgW2zSNCXCJ7UGPbDHj/faasvyTsB8luAj
v3gPqRYrRsyUL7wfSjk1aPXDwM5Ufembok7GQiEwMvzGXVlaILkjDtkGEIevfKOn
0Bp1yxQ5gM5YiBlX/UHEvg5qbv8DACgjlhutbCDDiD6I8dnEkjsUhSNhwY2G34e5
X1DSPCaRPzMmU5NigHS1KFnD6OBN1vRERMDJb75sK9kfUpunS03cSTyfBA18IfUA
fUw3JMeo2LJlyBNpSbyTIb4ECwvdPqpJQSVjEwIDAQABAoIBAF4BBpi6vBy09fxu
ISfoOpxZPBdkF+vJLSTW9oTmIYBuJEpavu1FReBqr7d/XTY6Rlr+NcAwEZnAc6+e
QxsPGvpselP5lX/C8mWtOh/AYW0ibdf9mCpZ3rAtcFQ0VzpQJYwa5a/Mhomw9HU9
taebjwmuw38SZM4BgKkq9kCaNu1L4g4oSOzHLaPXQQmE5yGgLWPe/2NE+TGVRNcU
eEQtH/8aV+tnYcm5EEplpQTwdwsidssI0QtDAfZZz2AyzeLpU9/piuVq+cKioaPe
GJWvqxquYWjE3y9/jPmub/+SMT8E/1uv5XKohbdQT+3MoW8/lYdsauqrKrGGjz0c
LMGuYAkCgYEA73v2JCECM/zL1+fDPqQJ9be+Q2Sysja/jFHpi/zJQfUDxb9aOMjS
YxB5pXRCbsQtrJplpq7QVCPxSfJ2fQnm9iTEhgFy49X5ddhUgDXNiUVc4hn6HtIy
MRdRJKenUOu0D9kagY0dUMIOnLter2ryw4LwMUr3r+K2v6+o84xyzO8CgYEAz99d
892jTcfwu4MQkxIVnSVj7rWHvRyucED3+0RuvaBizqDwbKCQzoalFXrumv7p6NGw
e+nuFEbd+GjEVk2EpPoF9fdZTXSRdl6TH8x2G9tXWVnXogNBILuyXNaIlnZ8XDkW
Fr46vjXgI5qUQgdu4JABK3Cix4rQ86v0WbT2lB0CgYEAuTdIML0OtSJojP0ENegs
g8ut7PVudwJ8touLcub4yHg0iLXrk0tN26wcSOhXkM9M+9cVkwpUuR5rOOO63A3S
gMAC9hkcwDT3EDtVbystYWMx6PRqS3gJtYnxCcZYUu9YfYFNTLDU4WaUYodPPaAb
TTZxic4PLgrLiAjVRDd1eiUCgYAEnKIK/QnYee0fW+MMQER2fhPfgeuHCJHeL7LQ
wk3qqxpGF0/+OPm9e0NCXL3adnleDvjpZuE/Vesqzbg9ae7dciabtGcozsNDawm8
lN6x84XWl6WvFH9naIKmiKPzIqHTsfiJfKL1AWD9qTpM1LljBg7gldkmsC++mDwN
mXQ3CQKBgQCVuf5/xnrA0rVjCSNEUdXepue4o5aksXPOyXryLs6lOTlRPjslVkAK
tz6ESC0nGUttK8jGfkqgQzuy4Mskf6/xYAiWneOUKNn5EUHRWc9PY6+xGmFqsAkq
souh0mwLgxZgkPOcWKWEu3mYCg8O+cgMErOsjesWw10DK0v2oX667A==
-----END RSA PRIVATE KEY-----`

func (s *ToySuite) TestSerializeHandshakeMessage(c *C) {
	m := &handshakeMessage{clientHelloType, []byte{0x01, 0x02, 0x03}}

	serialized := serializeHandshakeMessage(m)
	c.Assert(serialized, DeepEquals, []byte{
		0x01,             //type
		0x00, 0x00, 0x03, //size
		0x01, 0x02, 0x03, //message
	})
}

func (s *ToySuite) TestDeserializeHandshakeMessage(c *C) {
	m := []byte{
		0x01,             //type
		0x00, 0x00, 0x03, //size
		0x01, 0x02, 0x03, //message
	}
	expected := &handshakeMessage{clientHelloType, []byte{0x01, 0x02, 0x03}}

	d := deserializeHandshakeMessage(m)
	c.Assert(d, DeepEquals, expected)
}

func (s *ToySuite) TestSendClientHandshake(c *C) {
	client := newHandshakeClient()
	msg, err := client.sendClientHello()

	c.Assert(err, IsNil)
	c.Assert(len(msg), Equals, 0x29+4)
	c.Assert(msg[:6], DeepEquals, []byte{
		0x01,             // msg_type = client_hello
		0x00, 0x00, 0x29, //length

		//client_version
		0x03, 0x03, //ProtocolVersion
	})

	//We skip random (32 bytes)
	c.Assert(msg[38:], DeepEquals, []byte{
		//session_id (SessionID)
		0x00, //length

		//cipher_suites
		0x00, 0x02, // length
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_methods
		0x01, //length
		0x00, //NULL
	})
}

//TODO: test failure cases
func (s *ToySuite) TestReceiveClientHandshake(c *C) {
	client := newHandshakeClient()
	server := newHandshakeServer()

	msg, err := client.sendClientHello()
	c.Assert(err, IsNil)

	clientHello := deserializeHandshakeMessage(msg)
	c.Assert(clientHello.msgType, Equals, clientHelloType)

	toSend, err := server.receiveClientHello(clientHello.message)
	c.Assert(len(toSend[0]), Equals, 0x26+4)
	c.Assert(toSend[0][:6], DeepEquals, []byte{
		0x02, //server_hello

		0x00, 0x00, 0x26, // length

		//server_version
		0x03, 0x03, //ProtocolVersion
	})

	//We skip random (32 bytes)
	c.Assert(toSend[0][38:], DeepEquals, []byte{
		//session_id (SessionID)
		0x00, //length

		//cipher_suite
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_method
		0x00, //NULL
	})
}

func (s *ToySuite) TestSendServerCertificate(c *C) {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)
	c.Assert(len(cert.Certificate[0]), Equals, 0x0392)

	server := newHandshakeServer()
	server.Certificate = cert
	msg := server.sendCertificate()

	c.Assert(msg, DeepEquals, append([]byte{
		0x0b,           //certificate
		0x0, 0x3, 0x98, //length

		//certificate_list
		0x0, 0x3, 0x95, //length

		//first_certificate
		0x0, 0x3, 0x92, //length
	}, server.Certificate.Certificate[0]...))
}

func (s *ToySuite) TestSendServerHelloDone(c *C) {
	server := newHandshakeServer()
	msg, err := server.sendServerHelloDone()

	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, []byte{
		0x0e,             //certificate
		0x00, 0x00, 0x00, // length
	})
}

func (s *ToySuite) TestClientReceiveCertificate(c *C) {
	client := newHandshakeClient()
	server := newHandshakeServer()

	serverCertificate, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)

	server.Certificate = serverCertificate
	msg := server.sendCertificate()

	certificateMsg := deserializeHandshakeMessage(msg)
	err = client.receiveCertificate(certificateMsg.message)
	c.Assert(err, IsNil)
	c.Assert(client.serverCertificate.Raw, DeepEquals, serverCertificate.Certificate[0])

	N, _ := new(big.Int).SetString("24548513328370675094507991470476831003600372893349691632317324276903411581341034434646830710648908671472277683220758872058131286118696649158785935271592122592489413834251691703908594397311213755200032906999076652030291588339619221807652527300987723952469157142612358325478692255610581826939925994704999870494800062287313675347903379438382028305554675967808412681542977402706410386197294998891774251188902907133881071639348358639578195640030365276569419723808621669197133933717085059972644967247549111435457472750186935692907449081251149335706648080942241385740132003517840034878147839889761897721823225964298584285971", 10)
	serverPublicKey := &rsa.PublicKey{N: N, E: 65537}
	c.Assert(client.serverCertificate.PublicKey, DeepEquals, serverPublicKey)
}

func (s *ToySuite) TestClientReceiveServerHelloDone(c *C) {
	serverCertificate, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)

	client := newHandshakeClient()
	client.serverCertificate, _ = x509.ParseCertificate(serverCertificate.Certificate[0])

	toSend, err := client.receiveServerHelloDone([]byte{})
	c.Assert(err, IsNil)
	c.Assert(len(toSend), Equals, 1)

	encryptedPreMasterKey := deserializeHandshakeMessage(toSend[0])

	secretKey := serverCertificate.PrivateKey.(*rsa.PrivateKey)
	preMasterSecret, err := rsa.DecryptPKCS1v15(rand.Reader, secretKey, encryptedPreMasterKey.message[2:])

	c.Assert(err, IsNil)
	c.Assert(len(preMasterSecret), Equals, 48)
	c.Assert(preMasterSecret[:2], DeepEquals, []byte{0x03, 0x03})
}

func (s *ToySuite) TestClientReceiveCertificateRequestAndServerHelloDone(c *C) {
	serverCertificate, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)

	client := newHandshakeClient()
	client.serverCertificate, _ = x509.ParseCertificate(serverCertificate.Certificate[0])

	client.Certificate = serverCertificate //Will use the same, just for convenience
	client.receiveCertificateRequest([]byte{})

	toSend, err := client.receiveServerHelloDone([]byte{})
	c.Assert(err, IsNil)
	c.Assert(len(toSend), Equals, 2)

	c.Assert(toSend[0], DeepEquals, append([]byte{
		0x0b,           //certificate
		0x0, 0x3, 0x98, //length

		//certificate_list
		0x0, 0x3, 0x95, //length

		//first_certificate
		0x0, 0x3, 0x92, //length
	}, client.Certificate.Certificate[0]...))

	encryptedPreMasterKey := deserializeHandshakeMessage(toSend[1])

	secretKey := serverCertificate.PrivateKey.(*rsa.PrivateKey)
	preMasterSecret, err := rsa.DecryptPKCS1v15(rand.Reader, secretKey, encryptedPreMasterKey.message[2:])

	c.Assert(err, IsNil)
	c.Assert(len(preMasterSecret), Equals, 48)
	c.Assert(preMasterSecret[:2], DeepEquals, []byte{0x03, 0x03})
}

func (s *ToySuite) TestComputeMasterSecret(c *C) {
	preMasterSecret := [48]byte{
		0x03, 0x03, //version
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, //random
	}

	clientRandom := [32]byte{
		//random (Random)
		0x00, 0x00, 0x00, 0x00, //gmt_unix_time
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //random_bytes
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}

	serverRandom := [32]byte{
		//random (Random)
		0x01, 0x01, 0x01, 0x01, //gmt_unix_time
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //random_bytes
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}

	expected := [48]byte{
		0xff, 0xa4, 0xdf, 0xdb, 0x9b, 0x80, 0x5d, 0xa0, 0x24, 0xa2, 0x7d, 0x82,
		0x6f, 0xa9, 0x71, 0xb4, 0xc1, 0x32, 0x4a, 0xdc, 0xe9, 0x53, 0xf7, 0x7e,
		0x5a, 0x10, 0xdb, 0xa0, 0x3f, 0x2f, 0x92, 0xf6, 0x5f, 0x96, 0x87, 0x30,
		0xeb, 0x2c, 0xca, 0x90, 0xa7, 0xa1, 0x2b, 0x8a, 0xc8, 0x58, 0x1a, 0xd3,
	}

	masterSecret := computeMasterSecret(preMasterSecret[:], clientRandom[:], serverRandom[:])
	c.Assert(masterSecret, DeepEquals, expected)
}

func (s *ToySuite) TestGenerateVerifyData(c *C) {
	expected := []byte{
		0x4a, 0x2e, 0x34, 0x39, 0x12, 0x3b, 0x8f, 0xa5, 0xce, 0x9e, 0x96, 0x4a,
	}
	masterSecret := [48]byte{
		0xff, 0xa4, 0xdf, 0xdb, 0x9b, 0x80, 0x5d, 0xa0, 0x24, 0xa2, 0x7d, 0x82,
		0x6f, 0xa9, 0x71, 0xb4, 0xc1, 0x32, 0x4a, 0xdc, 0xe9, 0x53, 0xf7, 0x7e,
		0x5a, 0x10, 0xdb, 0xa0, 0x3f, 0x2f, 0x92, 0xf6, 0x5f, 0x96, 0x87, 0x30,
		0xeb, 0x2c, 0xca, 0x90, 0xa7, 0xa1, 0x2b, 0x8a, 0xc8, 0x58, 0x1a, 0xd3,
	}

	b := bytes.NewBuffer([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	verifyData, err := generateVerifyData(masterSecret[:], clientFinished, b)

	c.Assert(err, IsNil)
	c.Assert(verifyData, DeepEquals, expected)
}
