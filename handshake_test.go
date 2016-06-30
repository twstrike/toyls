package toyls

import . "gopkg.in/check.v1"

func serializeHandshakeMessage(m *handshakeMessage) []byte {
	msgLen := writeBytesFromUint24(uint32(len(m.message)))

	dst := make([]byte, 0, len(m.message)+4)
	dst = append(dst, byte(m.msgType))
	dst = append(dst, msgLen[:]...)
	return append(dst, m.message...)
}

func deserializeHandshakeMessage(m []byte) *handshakeMessage {
	msgType := m[0]
	messageLen, m := extractUint24(m[1:])
	message := make([]byte, messageLen)
	copy(message, m[:messageLen])

	return &handshakeMessage{
		msgType: handshakeType(msgType),
		message: message,
	}
}

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
