package toyls

import (
	"io"
	"net"
	"time"

	. "gopkg.in/check.v1"
)

func handshakenClientAndServer() (*Conn, *Conn) {
	connA := newClient()
	connB := newServer()

	connA.handshake.finished = true
	connB.handshake.finished = true

	keys := keysFromMasterSecret(securityParameters{
		encKeyLength:  32,
		fixedIVLength: 16,
		macKeyLength:  32,

		masterSecret: [48]byte{
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		},
		clientRandom: [32]byte{
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		},
		serverRandom: [32]byte{
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
			0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		},
	})

	connA.prepareCipherSpec(keys)
	connB.prepareCipherSpec(keys)

	//TODO: REMOVE ME after the IV is random
	connA.wp = keys
	connB.wp = keys

	connA.changeWriteCipherSpec()
	connB.changeReadCipherSpec()

	return connA, connB
}

func (s *ToySuite) TestConnHandleFragment(c *C) {
	conn := newClient()
	in := &mockConnIOReaderWriter{readwrite: []byte{22, 0x03, 0x03, 0x00, 0x01, 0x00, 22, 0x03, 0x03, 0x00, 0x01, 0x00}}
	cipherText, _ := conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS12)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})

	cipherText, _ = conn.handleFragment(in)

	c.Assert(cipherText.contentType, Equals, HANDSHAKE)
	c.Assert(cipherText.version, Equals, VersionTLS12)
	c.Assert(cipherText.length, Equals, uint16(1))
	c.Assert(cipherText.fragment, DeepEquals, []byte{0x00})
}

func (s *ToySuite) TestConnHandleStreamCipherText(c *C) {
	c.Skip("Not implemented yet")

	conn := newClient()
	conn.read.mac = nullMacAlgorithm{}

	ciphered := GenericStreamCipher{
		content: []byte{0x01, 0x02}, //TLSCompressed.length
	}
	cipherText := TLSCiphertext{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      uint16(len(ciphered.content)),
	}
	ciphered.MAC = conn.read.mac.MAC(nil, conn.write.sequenceNumber[0:], cipherText.header(), ciphered.content)

	cipherText.fragment = ciphered.Marshal()
	cipherText.length = uint16(len(cipherText.fragment))

	compressed, err := conn.handleCipherText(cipherText)

	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnHandleBlockCipherText(c *C) {
	_, connB := handshakenClientAndServer()

	cipherText := TLSCiphertext{
		contentType: 0x16,
		version:     protocolVersion{major: 0x3, minor: 0x3},
		length:      0x30,
		fragment: []uint8{
			0x28, 0x33, 0x45, 0x42, 0xfe, 0x43, 0xc3, 0x65,
			0x2, 0x19, 0x77, 0x2a, 0x41, 0xc0, 0x5a, 0x39,
			0x94, 0xcf, 0x16, 0x61, 0xec, 0x7c, 0x46, 0x49,
			0x9, 0xa6, 0xac, 0xdd, 0xf4, 0xdf, 0x6a, 0xc7,
			0x90, 0xab, 0x8c, 0xab, 0x32, 0xa2, 0x12, 0xfd,
			0x61, 0x2c, 0xb8, 0x83, 0xa5, 0xe2, 0xdc, 0x49,
		},
	}
	compressed, err := connB.handleCipherText(cipherText)

	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnHandleCompressed(c *C) {
	conn := newClient()
	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      3,
		fragment:    []byte{0x01, 0x02, 0x03},
	}

	conn.read.compression = nullCompressionMethod{}
	plaintext, err := conn.handleCompressed(compressed)
	c.Assert(err, IsNil)

	c.Assert(plaintext.contentType, Equals, HANDSHAKE)
	c.Assert(plaintext.version, Equals, VersionTLS12)
	c.Assert(plaintext.length, Equals, uint16(3))
	c.Assert(plaintext.fragment, DeepEquals, []byte{0x01, 0x02, 0x03})
}

func (s *ToySuite) TestConnStreamMacAndEncrypt(c *C) {
	c.Skip("not implemented")

	conn := newClient()
	compressed := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}
	cipherText, err := conn.macAndEncrypt(compressed)
	c.Assert(err, IsNil)
	compressed, err = conn.handleCipherText(cipherText)
	c.Assert(err, IsNil)
	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, uint16(2))
	c.Assert(compressed.fragment, DeepEquals, []byte{0x01, 0x02})
}

func (s *ToySuite) TestConnBlockMacAndEncrypt(c *C) {
	client, server := handshakenClientAndServer()
	expected := TLSCompressed{
		contentType: HANDSHAKE,
		version:     VersionTLS12,
		length:      2,
		fragment:    []byte{0x01, 0x02},
	}

	cipherText, err := client.macAndEncrypt(expected)
	c.Assert(err, IsNil)

	compressed, err := server.handleCipherText(cipherText)
	c.Assert(err, IsNil)

	c.Assert(compressed.contentType, Equals, HANDSHAKE)
	c.Assert(compressed.version, Equals, VersionTLS12)
	c.Assert(compressed.length, Equals, expected.length)
	c.Assert(compressed.fragment, DeepEquals, expected.fragment)
}

func (s *ToySuite) TestConnReadWriteBigText(c *C) {
	client, server := handshakenClientAndServer()
	rawConn := &mockConnIOReaderWriter{}
	client.rawConn = rawConn
	server.rawConn = rawConn

	sent := []byte(`
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	When to the sessions of sweet silent thought
	I summon up remembrance of things past,
	I sigh the lack of many a thing I sought,
	And with old woes new wail my dear times’ waste:
	Then can I drown an eye, unus’d to flow,
	For precious friends hid in death’s dateless night.
	And weep afresh love’s long-since cancell’d woe,
	And moan the expense of many a vanish’d sight.
	Then can I grieve at grievance foregone,
	And heavily from woe to woe tell o’er
	The sad account of fore-bemoaned moan,
	Which I new pay as if not paid before.
	But if the while I think on thee, dear friend,
	All losses are restor’d, and sorrows end.
	`)

	got := make([]byte, len(sent))

	client.SetChunkSize(0x00f0)
	client.Write(sent)
	server.Read(got)
	c.Assert(sent, DeepEquals, got)
}

func (s *ToySuite) TestConnFragment(c *C) {
	conn := newClient()
	fragmentLen := 0x10
	conn.SetChunkSize(uint16(fragmentLen))

	content := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	plainText, in, _ := conn.fragment(HANDSHAKE, VersionTLS12, content[:])
	c.Assert(plainText.contentType, Equals, HANDSHAKE)
	c.Assert(plainText.version, Equals, VersionTLS12)
	c.Assert(plainText.length, Equals, uint16(fragmentLen))
	c.Assert(plainText.fragment, DeepEquals, content[0:fragmentLen])

	plainText, in, _ = conn.fragment(HANDSHAKE, VersionTLS12, in)
	c.Assert(plainText.contentType, Equals, HANDSHAKE)
	c.Assert(plainText.version, Equals, VersionTLS12)
	c.Assert(plainText.length, Equals, uint16(fragmentLen))
	c.Assert(plainText.fragment, DeepEquals, content[fragmentLen:])
}

type mockConnIOReaderWriter struct {
	readwrite []byte
	readIndex int
	errCount  int
	err       error

	calledClose int
}

func (iom *mockConnIOReaderWriter) Read(p []byte) (n int, err error) {
	if iom.readIndex >= len(iom.readwrite) {
		return 0, io.EOF
	}
	i := copy(p, iom.readwrite[iom.readIndex:])
	iom.readIndex += i
	var e error
	if iom.errCount == 0 {
		e = iom.err
	}
	iom.errCount--
	return i, e
}

func (iom *mockConnIOReaderWriter) Write(p []byte) (n int, err error) {
	iom.readwrite = append(iom.readwrite, p...)
	var e error
	if iom.errCount == 0 {
		e = iom.err
	}
	iom.errCount--
	return len(p), e
}

func (iom *mockConnIOReaderWriter) Close() error {
	iom.calledClose++
	return nil
}

func (iom *mockConnIOReaderWriter) LocalAddr() net.Addr {
	return nil
}

func (iom *mockConnIOReaderWriter) RemoteAddr() net.Addr {
	return nil
}

func (iom *mockConnIOReaderWriter) SetDeadline(time.Time) error {
	return nil
}

func (iom *mockConnIOReaderWriter) SetReadDeadline(time.Time) error {
	return nil
}

func (iom *mockConnIOReaderWriter) SetWriteDeadline(time.Time) error {
	return nil
}
