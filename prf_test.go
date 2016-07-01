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
		mac_key_length:  1,
		enc_key_length:  2,
		fixed_iv_length: 3,
		master_secret:   [48]byte{},
		client_random:   [32]byte{},
		server_random:   [32]byte{},
	}
	writeParams := keysFromMasterSecret(params)
	c.Assert(len(writeParams.clientMAC), Equals, int(params.mac_key_length))
	c.Assert(len(writeParams.serverMAC), Equals, int(params.mac_key_length))
	c.Assert(len(writeParams.clientKey), Equals, int(params.enc_key_length))
	c.Assert(len(writeParams.serverKey), Equals, int(params.enc_key_length))
	c.Assert(len(writeParams.clientIV), Equals, int(params.fixed_iv_length))
	c.Assert(len(writeParams.serverIV), Equals, int(params.fixed_iv_length))
}
