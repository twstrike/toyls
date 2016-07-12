package toyls

import (
	"flag"
	"net"

	"crypto/tls"

	. "gopkg.in/check.v1"
)

var live = flag.Bool("live", false, "Include live tests")

type LiveToySuite struct{}

var _ = Suite(&LiveToySuite{})

func (s *LiveToySuite) SetUpSuite(c *C) {
	if !*live {
		c.Skip("-live not provided")
	}
}

func (s *LiveToySuite) TestClientHandshake(c *C) {
	c.Skip("not now")

	conn, err := Dial("tcp", "mail.google.com:443")
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Close()
}

func (s *LiveToySuite) TestServerHandshake(c *C) {
	pem := []byte(rsaCertPEM + rsaKeyPEM)
	cert, err := tls.X509KeyPair(pem, pem)
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)
	c.Assert(len(cert.Certificate[0]), Equals, 0x01d7)

	l, err := net.Listen("tcp", ":12345")
	c.Assert(err, IsNil)

	done := make(chan bool, 0)
	go func() {
		conn, err := l.Accept()
		c.Assert(err, IsNil)

		server := newServer()
		server.handshaker.(*handshakeServer).Certificate = cert
		server.rawConn = conn
		server.doHandshake()
		done <- true
	}()

	conn, err := tls.Dial("tcp", ":12345", &tls.Config{
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	})

	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Close()

	<-done
}
