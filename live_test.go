package toyls

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
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
	conn := newClient()
	conn.rawConn = rawConn
	return conn, err
}

func (c *Conn) Handshake() {
	clientHello, _ := c.handshakeClient.sendClientHello()
	tosend, _ := c.send(HANDSHAKE, VersionTLS12, clientHello)
	c.rawConn.Write(tosend)
	response, err := ioutil.ReadAll(bufio.NewReader(c.rawConn))
	if err != nil {
		fmt.Println(err.Error())
	}
	c.receive(response)
	return
}

func (c *Conn) Close() {
	c.rawConn.Close()
	return
}
