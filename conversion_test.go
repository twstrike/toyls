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
