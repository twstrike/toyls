package toyls

import . "gopkg.in/check.v1"

func (s *ToySuite) TestSerializeHandshakeMessage(c *C) {
	m := &handshakeMessage{clientHelloType, []byte{0x01, 0x02, 0x03}}

	serialized := serializeHandshakeMessage(m)
	c.Assert(serialized, DeepEquals, []byte{
		0x01,             //type
		0x00, 0x00, 0x03, //size
		0x01, 0x02, 0x03, //message
	})
}

func (s *ToySuite) TestDeserializeHandshakeMessage(c *C) {
	m := []byte{
		0x01,             //type
		0x00, 0x00, 0x03, //size
		0x01, 0x02, 0x03, //message
	}
	expected := &handshakeMessage{clientHelloType, []byte{0x01, 0x02, 0x03}}

	d := deserializeHandshakeMessage(m)
	c.Assert(d, DeepEquals, expected)
}

func (s *ToySuite) TestSendClientHandshake(c *C) {
	client := newHandshakeClient()
	msg, err := client.sendClientHello()

	c.Assert(err, IsNil)
	c.Assert(len(msg), Equals, 0x29+4)
	c.Assert(msg[:6], DeepEquals, []byte{
		0x01,             // msg_type = client_hello
		0x00, 0x00, 0x29, //length

		//client_version
		0x03, 0x03, //ProtocolVersion
	})

	//We skip random (32 bytes)
	c.Assert(msg[38:], DeepEquals, []byte{
		//session_id (SessionID)
		0x00, //length

		//cipher_suites
		0x00, 0x02, // length
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_methods
		0x01, //length
		0x00, //NULL
	})
}

//TODO: test failure cases
func (s *ToySuite) TestReceiveClientHandshake(c *C) {
	client := newHandshakeClient()
	server := newHandshakeServer()

	msg, err := client.sendClientHello()
	c.Assert(err, IsNil)

	clientHello := deserializeHandshakeMessage(msg)
	c.Assert(clientHello.msgType, Equals, clientHelloType)

	msg, err = server.receiveClientHello(clientHello.message)
	c.Assert(len(msg), Equals, 0x26+4)
	c.Assert(msg[:6], DeepEquals, []byte{
		0x02, //server_hello

		0x00, 0x00, 0x26, // length

		//server_version
		0x03, 0x03, //ProtocolVersion
	})

	//We skip random (32 bytes)
	c.Assert(msg[38:], DeepEquals, []byte{
		//session_id (SessionID)
		0x00, //length

		//cipher_suite
		0x00, 0x2f, // CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA

		//compression_method
		0x00, //NULL
	})
}
