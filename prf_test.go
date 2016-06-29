package toyls

import . "gopkg.in/check.v1"

func (s *ToySuite) TestPRF(c *C) {
	secret := []byte{0x01}
	label := "slithy toves"
	seed := []byte{0x01}

	result := make([]byte, 5)
	prf(result, secret, label, seed)

	c.Assert(result, DeepEquals, []byte{0xe9, 0x98, 0xd, 0xad, 0xa3})
}
