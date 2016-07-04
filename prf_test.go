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

func (s *ToySuite) TestKeysFromMasterSecret(c *C) {
	params := securityParameters{
		macKeyLength:  1,
		encKeyLength:  2,
		fixedIVLength: 3,
		masterSecret:  [48]byte{},
		clientRandom:  [32]byte{},
		serverRandom:  [32]byte{},
	}
	writeParams := keysFromMasterSecret(params)
	c.Assert(len(writeParams.clientMAC), Equals, int(params.macKeyLength))
	c.Assert(len(writeParams.serverMAC), Equals, int(params.macKeyLength))
	c.Assert(len(writeParams.clientKey), Equals, int(params.encKeyLength))
	c.Assert(len(writeParams.serverKey), Equals, int(params.encKeyLength))
	c.Assert(len(writeParams.clientIV), Equals, int(params.fixedIVLength))
	c.Assert(len(writeParams.serverIV), Equals, int(params.fixedIVLength))
}
