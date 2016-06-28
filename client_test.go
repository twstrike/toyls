package toyls

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ToySuite struct{}

var _ = Suite(&ToySuite{})

func (s *ToySuite) TestClientHandshake(c *C) {
	client := newHandshakeClient()
	msg, err := deserializeClientHello(client.sendClientHello())

	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, &clientHelloBody{})
}
