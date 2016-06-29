package toyls

import . "gopkg.in/check.v1"

func (s *ToySuite) TestExtractUint16(c *C) {
	data := []byte{
		0x12, 0x34, 0x45,
	}

	n, p := extractUint16(data)
	c.Assert(n, Equals, uint16(0x1234))
	c.Assert(p, DeepEquals, data[2:])
}

func (s *ToySuite) TestExtractUint32(c *C) {
	data := []byte{
		0x12, 0x34, 0x56, 0x78, 0x90,
	}

	n, p := extractUint32(data)
	c.Assert(n, Equals, uint32(0x12345678))
	c.Assert(p, DeepEquals, data[4:])
}

func (s *ToySuite) TestWriteBytesFromUint16(c *C) {
	n := uint16(0x1234)
	b := writeBytesFromUint16(n)

	exp := [2]byte{
		0x12, 0x34,
	}

	c.Assert(b, DeepEquals, exp)
}

func (s *ToySuite) TestWriteBytesFromUint24(c *C) {
	n := uint32(0x123456)
	b := writeBytesFromUint24(n)

	exp := [3]byte{
		0x12, 0x34, 0x56,
	}

	c.Assert(b, DeepEquals, exp)
}

func (s *ToySuite) TestWriteBytesFromUint32(c *C) {
	n := uint32(0x12345678)
	exp := [4]byte{
		0x12, 0x34, 0x56, 0x78,
	}
	b := writeBytesFromUint32(n)
	c.Assert(b, DeepEquals, exp)
}
