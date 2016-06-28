package toyls

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
