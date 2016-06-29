package toyls

import (
	"errors"
	"math"
)

const (
	cipherSuiteLen     = 2
	randomLen          = 32
	protocolVersionLen = 2
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
	vectorLen, p := extractUint16(src)
	if vectorLen < 2 || vectorLen > uint16(math.Pow(2, 16))-2 {
		return nil, p, errors.New("The cipher suite vector should contain <2..2^16-2> bytes.")
	}

	n := vectorLen / cipherSuiteLen
	dst := make([]cipherSuite, n)

	for i := 0; i < len(dst); i++ {
		s := &dst[i]
		copy(s[:], p[i*2:i*2+2])
	}

	return dst, p[vectorLen:], nil
}

func extractCipherSuite(dst, src []byte) []byte {
	copy(dst, src[:2])
	return src[2:]
}

func extractCompressionMethods(src []byte) ([]byte, []byte, error) {
	vectorLen := int(src[0])
	if vectorLen < 1 || vectorLen > int(math.Pow(2, 8))-1 {
		return nil, src[1:], errors.New("The compression methods vector should contain <1..2^8-2> bytes.")
	}

	compressionMethods := make([]byte, vectorLen)
	copy(compressionMethods, src[1:1+vectorLen])

	return compressionMethods, src[1+vectorLen:], nil
}

func writeBytesFromUint16(n uint16) (dst [2]byte) {
	dst[0] = byte(n >> 8 & 0xff)
	dst[1] = byte(n & 0xff)

	return
}

func writeBytesFromUint24(n uint32) (dst [3]byte) {
	dst[0] = byte(n >> 16 & 0xff)
	dst[1] = byte(n >> 8 & 0xff)
	dst[2] = byte(n & 0xff)

	return
}

func writeBytesFromUint32(n uint32) (dst [4]byte) {
	dst[0] = byte(n >> 24 & 0xff)
	dst[1] = byte(n >> 16 & 0xff)
	dst[2] = byte(n >> 8 & 0xff)
	dst[3] = byte(n & 0xff)

	return
}
