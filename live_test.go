package toyls

import (
	"flag"
	"fmt"
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
	fmt.Println("Alice ClientHello ---------> Bob")
	fmt.Println("Alice <--------- ServerHello Bob")
	fmt.Println("Alice <--------- Certificate Bob")
	fmt.Println("Alice <----- ServerHelloDone Bob")
	fmt.Println("Alice ClientKeyExchange ---> Bob")
	fmt.Println("Alice ChangeCipherSpec ----> Bob")
	fmt.Println("Alice Finished ------------> Bob")
	fmt.Println("Alice <----------- Finished  Bob")
	clientHello, _ := c.hello()
	c.rawConn.Write(clientHello)
	toSends := make(chan [][]byte, 1024)
	toSends = c.receive(c.rawConn)
	for {
		toSend := <-toSends
		for i := range toSend {
			c.rawConn.Write(toSend[i])
		}
	}
	return
}
