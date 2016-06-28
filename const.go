package toytls

const (
	TLS_RSA_WITH_AES_128_CBC_SHA       uint16 = 0x002f
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA uint16 = 0xc013

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00.
	// TLS_FALLBACK_SCSV uint16 = 0x5600
)
