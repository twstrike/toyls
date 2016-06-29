package toyls

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ToySuite struct{}

var _ = Suite(&ToySuite{})

func (s *ToySuite) TestClientHandshake(c *C) {
	c.Skip("comming soon")
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
		0x0A,                                                       //length
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, //SessionID

		//cipher_suites
		0x00, 0x02, // length
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_methods
		0x01, //length
		0x00, //NULL
	}

	msg, err := deserializeClientHello(helloBody)

	expected := &clientHelloBody{
		clientVersion: protocolVersion{0x03, 0x03},
		random: random{
			0,
			[28]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		},
		sessionID:          []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
		cipherSuites:       []cipherSuite{cipherSuite{0x00, 0x2f}},
		compressionMethods: []byte{0x00},
	}
	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, expected)
}

func deserializeClientHello(h []byte) (*clientHelloBody, error) {
	hello := &clientHelloBody{}

	hello.clientVersion.major = h[0]
	hello.clientVersion.minor = h[1]

	hello.random.gmtUnixTime, h = extractUint32(h[2:])
	copy(hello.random.randomBytes[:], h[:28])

	sessionLen := int(h[28])
	hello.sessionID = make([]byte, sessionLen)
	copy(hello.sessionID, h[29:29+sessionLen])

	ciphersStart := 29 + sessionLen
	ciphers, h := extractUint16(h[ciphersStart:])
	//TODO validate ciphers is 2 < x < 2^16-2
	hello.cipherSuites = make([]cipherSuite, ciphers/2)
	for i := 0; i < int(ciphers)/2; i++ {
		s := &hello.cipherSuites[i]
		copy(s[:], h[i*2:i*2+2])
	}

	compressionStart := int(ciphers)
	compressions := int(h[compressionStart])
	hello.compressionMethods = make([]byte, compressions)
	copy(hello.compressionMethods[:], h[compressionStart+1:compressionStart+1+compressions])

	return hello, nil
}
