package toyls

import (
	"flag"
	"fmt"
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

func (s *LiveToySuite) TestHandshakeAndApplicationData(c *C) {
	pem := []byte(rsaCertPEM + rsaKeyPEM)
	cert, err := tls.X509KeyPair(pem, pem)
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)
	c.Assert(len(cert.Certificate[0]), Equals, 0x01d7)

	l, err := net.Listen("tcp", ":12345")
	c.Assert(err, IsNil)

	handshakeDone := make(chan bool, 0)
	go func() {
		conn, err := l.Accept()
		c.Assert(err, IsNil)

		server := newServer()
		server.handshaker.(*handshakeServer).Certificate = cert
		server.rawConn = conn
		server.doHandshake()
		<-handshakeDone

		reply := make([]byte, 12)
		server.Read(reply)
		fmt.Println("Server Receive:", string(reply))
		server.Write([]byte("hello client"))
	}()

	conn, err := Dial("tcp", ":12345")
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	handshakeDone <- true

	conn.Write([]byte("hello server"))

	reply := make([]byte, 6)
	conn.Read(reply)
	fmt.Println("Client Receive:", string(reply))
	reply = make([]byte, 6)
	conn.Read(reply)
	fmt.Println("Client Receive:", string(reply))

	conn.Close()
}
