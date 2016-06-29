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
	return nil, nil
}
