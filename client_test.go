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

func (s *ToySuite) TestDeserializeClientHello(c *C) {
	helloBody := []byte{
		//client_version
		0x03, 0x03, //ProtocolVersion

		//random (Random)
		0x00, 0x00, 0x00, 0x00, //gmt_unix_time
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //random_bytes
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,

		//session_id (SessionID)
		0x10,                                                       //length
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, //SessionID

		//cipher_suites
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // length
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_methods
		0x00, //NULL
	}

	msg, err := deserializeClientHello(helloBody)

	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, &clientHelloBody{})
}
