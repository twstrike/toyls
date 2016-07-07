package toyls

import (
	"flag"
	"net"

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
	conn, err := Dial("tcp", "mail.google.com:443")
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Handshake()
	conn.Close()
}

func Dial(network, addr string) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr)
}

func DialWithDialer(dialer *net.Dialer, network, addr string) (*Conn, error) {
	rawConn, err := dialer.Dial(network, addr)
	conn := NewConn(SERVER)
	conn.rawConn = rawConn
	return conn, err
}
