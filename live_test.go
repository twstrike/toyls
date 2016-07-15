package toyls

import (
	"flag"
	"fmt"
	"net"
	"time"

	"crypto/tls"
	"crypto/x509"

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
	c.Skip("sleep")
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)
	c.Assert(len(cert.Certificate[0]), Equals, 0x0392)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rsaCertPEM))
	c.Assert(ok, Equals, true)
	tlsConf := &tls.Config{
		RootCAs: roots,
		//Time:    func() time.Time { return time.Unix(0, 0) },
	}

	l, err := net.Listen("tcp", ":12345")
	c.Assert(err, IsNil)

	go func() {
		conn, err := l.Accept()
		c.Assert(err, IsNil)

		server := newServer()
		server.handshaker.(*handshakeServer).Certificate = cert
		server.rawConn = conn

		reply := make([]byte, 12)
		server.Read(reply)
		c.Assert(reply, DeepEquals, []byte("hello server"))

		server.Write([]byte("hello client"))
	}()

	conn, err := Dial("tcp", ":12345", tlsConf)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	_, err = conn.Write([]byte("hello server"))
	c.Assert(err, IsNil)

	reply := make([]byte, 6)
	conn.Read(reply)
	c.Assert(reply, DeepEquals, []byte("hello "))

	reply = make([]byte, 6)
	conn.Read(reply)
	c.Assert(reply, DeepEquals, []byte("client"))

	defer func() {
		c.Assert(recover(), NotNil)
	}()
	conn.SetReadDeadline(time.Now())
	reply = make([]byte, 1)
	conn.Read(reply)
}

func (s *LiveToySuite) TestHandshakeAndApplicationDataECDHE(c *C) {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	c.Assert(err, IsNil)
	c.Assert(len(cert.Certificate), Equals, 1)

	l, err := net.Listen("tcp", ":12346")
	c.Assert(err, IsNil)

	conn, err := l.Accept()
	c.Assert(err, IsNil)

	server := newServer()
	server.handshaker.(*handshakeServer).Certificate = cert
	server.rawConn = conn
	server.doHandshake()

	reply := make([]byte, 12)
	server.Read(reply)
	fmt.Println("Server Receive:", string(reply))
	server.Write([]byte("hello client"))
}
