package toyls

import (
	"errors"
	"math"
)

func extractUint16(src []byte) (n uint16, p []byte) {
	n |= uint16(src[0]) << 8
	n |= uint16(src[1])
	p = src[2:]

	return
}

func extractUint32(src []byte) (n uint32, p []byte) {
	n |= uint32(src[0]) << 24
	n |= uint32(src[1]) << 16
	n |= uint32(src[2]) << 8
	n |= uint32(src[3])
	p = src[4:]

	return
}

const (
	cipherSuiteLen = 2
)

func extractProtocolVersion(src []byte) (protocolVersion, []byte) {
	return protocolVersion{
		src[0], src[1],
	}, src[2:]
}

func extractRandom(src []byte) (random, []byte) {
	r := random{}
	r.gmtUnixTime, src = extractUint32(src)
	copy(r.randomBytes[:], src[:28])

	return r, src[28:]
}

func extractSessionID(src []byte) ([]byte, []byte) {
	sessionLen := int(src[0])
	sessionID := make([]byte, sessionLen)
	copy(sessionID, src[1:1+sessionLen])

	return sessionID, src[1+sessionLen:]
}

func extractCipherSuites(src []byte) ([]cipherSuite, []byte, error) {
	ciphersLen, p := extractUint16(src)
	if ciphersLen < 2 || ciphersLen > uint16(math.Pow(2, 16))-2 {
		return nil, p, errors.New("The cipher suite vector should contain <2..2^16-2> bytes.")
	}

	n := ciphersLen / cipherSuiteLen
	dst := make([]cipherSuite, n)

	for i := 0; i < len(dst); i++ {
		s := &dst[i]
		copy(s[:], p[i*2:i*2+2])
	}

	return dst, p[ciphersLen:], nil
}

func extractCompressionMethods(src []byte) ([]byte, []byte) {
	//TODO: Validate compressionMethodsSize
	compressions := int(src[0])
	compressionMethods := make([]byte, compressions)
	copy(compressionMethods, src[1:1+compressions])

	return compressionMethods, src[1+compressions:]
}
