package toyls

import (
	"crypto/tls"

	. "gopkg.in/check.v1"
)

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
`

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

	msg, err = server.receiveClientHello(clientHello.message)
	c.Assert(len(msg), Equals, 0x26+4)
	c.Assert(msg[:6], DeepEquals, []byte{
		0x02, //server_hello

		0x00, 0x00, 0x26, // length

		//server_version
		0x03, 0x03, //ProtocolVersion
	})

	//We skip random (32 bytes)
	c.Assert(msg[38:], DeepEquals, []byte{
		//session_id (SessionID)
		0x00, //length

		//cipher_suite
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_method
		0x00, //NULL
	})
}

func (s *ToySuite) TestSendServerCertificate(c *C) {
	pem := []byte(rsaCertPEM + rsaKeyPEM)
	cert, err := tls.X509KeyPair(pem, pem)
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)
	c.Assert(len(cert.Certificate[0]), Equals, 0x01d7)

	server := newHandshakeServer()
	server.Certificate = cert
	msg, err := server.sendCertificate()

	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, append([]byte{
		0x0b,             //certificate
		0x00, 0x01, 0xdd, // length

		//certificate_list
		0x00, 0x01, 0xda, //length

		//first_certificate
		0x00, 0x01, 0xd7, //length
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