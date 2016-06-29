package toyls

func deserializeServerHello(h []byte) (*serverHelloBody, error) {
	hello := &serverHelloBody{}

	hello.serverVersion, h = extractProtocolVersion(h)
	hello.random, h = extractRandom(h)
	hello.sessionID, h = extractSessionID(h)
	h = extractCipherSuite(hello.cipherSuite[:], h)
	hello.compressionMethod = h[0]

	//XXX It never fails
	return hello, nil
}

func serializeServerHello(h *serverHelloBody) ([]byte, error) {
	compressionMethodLen := 1
	sessionIDLen := len(h.sessionID)
	vectorSizesLen := 4
	capacity := protocolVersionLen + randomLen + cipherSuiteLen + compressionMethodLen + sessionIDLen + vectorSizesLen

	hello := make([]byte, 0, capacity)
	hello = append(hello, h.serverVersion.major, h.serverVersion.minor)

	gmtUnixTime := writeBytesFromUint32(h.random.gmtUnixTime)
	hello = append(hello, gmtUnixTime[:]...)
	hello = append(hello, h.random.randomBytes[:]...)

	hello = append(hello, byte(sessionIDLen))
	hello = append(hello, h.sessionID...)

	hello = append(hello, h.cipherSuite[:]...)
	hello = append(hello, h.compressionMethod)

	return hello, nil
}

func deserializeCertificate() {
	//TODO
}

func serializeCertificate(c *certificateBody) ([]byte, error) {
	certListBody := make([]byte, 0, 0xffffff) // 2^24-1 is maximim length
	for _, ci := range c.certificateList {
		//XXX check len(ci). It should be less than 0xFFFFFF
		certificateLen := writeBytesFromUint24(uint32(len(ci)))
		certListBody = append(certListBody, certificateLen[:]...)
		certListBody = append(certListBody, ci...)
	}

	certificateListLen := writeBytesFromUint24(uint32(len(certListBody)))
	cert := append(certificateListLen[:], certListBody...)

	return cert, nil
}
