package toyls

import (
	"flag"

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
	conn.Close()
}
