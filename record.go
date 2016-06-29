package toyls

type ConnectionEnd uint8

var (
	SERVER ConnectionEnd = 0
	CLIENT ConnectionEnd = 1
)

type SecurityParameters struct {
	entity                ConnectionEnd
	prf_algorithm         PRFAlgorithm
	bulk_cipher_algorithm BulkCipherAlgorithm
	cipher                CipherType
	enc_key_length        uint8
	block_length          uint8
	fixed_iv_length       uint8
	record_iv_length      uint8
	mac_algorithm         MACAlgorithm
	mac_length            uint8
	mac_key_length        uint8
	compression_algorithm CompressionMethod
	master_secret         [48]byte
	client_random         [32]byte
	server_random         [32]byte
}

type PRFAlgorithm interface{}
type CipherType interface{}
type BulkCipherAlgorithm interface{}
type MACAlgorithm interface{}

type CompressionMethod interface {
	compress([]byte) ([]byte, uint16)
	decompress([]byte) ([]byte, uint16)
}

type nullCompressionMethod struct{}

func (nullCompressionMethod) compress(data []byte) ([]byte, uint16) {
	return data, uint16(len(data))
}

func (nullCompressionMethod) decompress(compressed []byte) ([]byte, uint16) {
	return compressed, uint16(len(compressed))
}

type ConnectionState struct {
	compression_state uint8
	cipher_state      uint8
	mac_key           []byte
	sequence_number   uint64
}

type ContentType uint8

var (
	CHANGE_CIPHER_SPEC ContentType = 20
	ALERT              ContentType = 21
	HANDSHAKE          ContentType = 22
	APPLICATION_DATA   ContentType = 23
	// other           ContentType = 255
)

type protocolVersion struct {
	major uint8
	minor uint8
}

var (
	VersionSSL30 = protocolVersion{0x03, 0x00}
	VersionTLS10 = protocolVersion{0x03, 0x01}
	VersionTLS11 = protocolVersion{0x03, 0x02}
	VersionTLS12 = protocolVersion{0x03, 0x03}
)

type TLSPlaintext struct {
	contentType ContentType
	version     protocolVersion
	length      uint16
	fragment    []byte //TLSPlaintext.length MUST NOT exceed 2^14.
}

type TLSCompressed struct {
	contentType ContentType
	version     protocolVersion
	length      uint16
	fragment    []byte //TLSCompressed.length MUST NOT exceed 2^14 + 1024.
}

type TLSCiphertext struct {
	contentType ContentType
	version     protocolVersion
	length      uint16
	// select (SecurityParameters.cipher_type) {
	//     case stream: GenericStreamCipher;
	//     case block:  GenericBlockCipher;
	//     case aead:   GenericAEADCipher;
	// } fragment;
	fragment []byte //TLSCiphertext.length MUST NOT exceed 2^14 + 2048.
}

type Ciphered interface {
	Marshal() []byte
	UnMarshal([]byte, SecurityParameters) Ciphered
}

type GenericStreamCipher struct {
	content []byte //TLSCompressed.length
	MAC     []byte //SecurityParameters.mac_length
	/*
		MAC(MAC_write_key, seq_num + TLSCompressed.type +
		TLSCompressed.version +
		TLSCompressed.length +
		TLSCompressed.fragment);
	*/
}

func (c GenericStreamCipher) Marshal() []byte {
	ret := []byte{}
	ret = append(ret, c.content...)
	ret = append(ret, c.MAC...)
	return ret
}

func (c GenericStreamCipher) UnMarshal(fragment []byte, params SecurityParameters) GenericStreamCipher {
	c.content = fragment[:len(fragment)-int(params.mac_length)]
	c.MAC = fragment[len(fragment)-int(params.mac_length):]
	return c
}

type GenericBlockCipher struct {
	IV             []byte //SecurityParameters.record_iv_length
	content        []byte //TLSCompressed.length
	MAC            []byte //SecurityParameters.mac_length
	padding        []byte //GenericBlockCipher.padding_length
	padding_length uint8
}

func (c GenericBlockCipher) Marshal() []byte {
	ret := []byte{}
	ret = append(ret, c.IV...)
	ret = append(ret, c.content...)
	ret = append(ret, c.MAC...)
	ret = append(ret, c.padding...)
	ret = append(ret, c.padding_length)
	return ret
}

func (c GenericBlockCipher) UnMarshal(fragment []byte, params SecurityParameters) GenericBlockCipher {
	c.IV = fragment[:params.record_iv_length]
	c.padding_length = fragment[len(fragment)-1]
	c.padding = fragment[len(fragment)-1-int(c.padding_length) : len(fragment)-1]
	c.MAC = fragment[len(fragment)-1-int(c.padding_length)-int(params.mac_length) : len(fragment)-1-int(c.padding_length)]
	c.content = fragment[params.record_iv_length : len(fragment)-1-int(c.padding_length)-int(params.mac_length)]
	return c
}

type GenericAEADCipher struct {
	nonce_explicit []byte //SecurityParameters.record_iv_length
	content        []byte //TLSCompressed.length
}

func (c GenericAEADCipher) Marshal() []byte {
	ret := []byte{}
	ret = append(ret, c.nonce_explicit...)
	ret = append(ret, c.content...)
	return ret
}

func (c GenericAEADCipher) UnMarshal(fragment []byte, params SecurityParameters) GenericAEADCipher {
	c.nonce_explicit = fragment[:params.record_iv_length]
	c.content = fragment[params.record_iv_length:]
	return c
}
