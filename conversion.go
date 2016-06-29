package toyls

import "errors"

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

func extractCipherSuites(src []byte) ([]cipherSuite, []byte, error) {
	ciphersLen, p := extractUint16(src)
	if ciphersLen < 2 || ciphersLen > 2^16-1 {
		return nil, p, errors.New("The cipher suite list should contain <2..2^16-2> elements.")
	}

	n := ciphersLen / cipherSuiteLen
	dst := make([]cipherSuite, n)

	for i := 0; i < len(dst); i++ {
		s := &dst[i]
		copy(s[:], p[i*2:i*2+2])
	}

	return dst, p[ciphersLen:], nil
}
