package toyls

import (
	"crypto/cipher"
	"hash"
)

type recordProtocol interface {
	readRecord(ContentType) ([]byte, error)
	writeRecord(ContentType, []byte) error
	establishKeys([48]byte, [32]byte, [32]byte)
}

type connectionEnd uint8

const (
	SERVER connectionEnd = 0
	CLIENT               = 1
)

type securityParameters struct {
	entity               connectionEnd
	prfAlgorithm         prfAlgorithm
	bulkCipherAlgorithm  bulkCipherAlgorithm
	inCipher             cipherType
	outCipher            cipherType
	encKeyLength         uint8
	blockLength          uint8
	fixedIVLength        uint8
	recordIVLength       uint8
	macAlgorithm         macAlgorithm
	macKeyLength         uint8
	compressionAlgorithm compressionMethod
	masterSecret         [48]byte
	clientRandom         [32]byte
	serverRandom         [32]byte
}

type prfAlgorithm interface{}
type cipherType interface{}

type nullStreamCipher struct{}

func (nullStreamCipher) XORKeyStream(dst, src []byte) {
	return
}

//XXX This is not used
type cbcBlockCipher struct {
	cipher.BlockMode
	iv []byte
}

func (cbc cbcBlockCipher) SetIV(iv []byte) {
	copy(cbc.iv, iv)
}

type bulkCipherAlgorithm interface{}

type macAlgorithm interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

type nullMacAlgorithm struct{}

func (s nullMacAlgorithm) Size() int {
	return 0
}

func (s nullMacAlgorithm) MAC(digestBuf, seq, header, data []byte) []byte {
	return []byte{}
}

type hmacAlgorithm struct {
	h hash.Hash
}

func (s hmacAlgorithm) Size() int {
	return s.h.Size()
}

func (s hmacAlgorithm) MAC(digestBuf, seq, header, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
}

type compressionMethod interface {
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

type connectionState struct {
	compressionState    uint8
	cipherState         uint8
	macKey              []byte
	readSequenceNumber  [8]byte //uint64
	writeSequenceNumber [8]byte //uint64
}

type ContentType uint8

var (
	CHANGE_CIPHER_SPEC ContentType = 0x14
	ALERT              ContentType = 0x15
	HANDSHAKE          ContentType = 0x16
	APPLICATION_DATA   ContentType = 0x17
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

type writeParams struct {
	clientMAC,
	serverMAC,
	clientKey,
	serverKey,
	clientIV,
	serverIV []byte
}

type TLSPlaintext struct {
	contentType ContentType
	version     protocolVersion
	length      uint16 //is this len(fragment)?
	fragment    []byte //TLSPlaintext.length MUST NOT exceed 2^14.
}

type TLSCompressed struct {
	contentType ContentType
	version     protocolVersion
	length      uint16 //is this len(fragment)?
	fragment    []byte //TLSCompressed.length MUST NOT exceed 2^14 + 1024.
}

type TLSCiphertext struct {
	contentType ContentType
	version     protocolVersion
	length      uint16 //is this len(fragment)?
	// select (SecurityParameters.cipher_type) {
	//     case stream: GenericStreamCipher;
	//     case block:  GenericBlockCipher;
	//     case aead:   GenericAEADCipher;
	// } fragment;
	fragment []byte //TLSCiphertext.length MUST NOT exceed 2^14 + 2048.
}

func (t TLSCiphertext) serialize() (ret []byte) {
	ret = append(ret, byte(t.contentType))
	ret = append(ret, t.version.major)
	ret = append(ret, t.version.minor)
	ret = append(ret, (byte)(t.length>>8))
	ret = append(ret, (byte)(t.length))
	ret = append(ret, t.fragment...)
	return ret
}

func (t TLSCiphertext) header() (ret []byte) {
	return append(ret[:0], byte(t.contentType), t.version.major, t.version.minor, (byte)(t.length>>8), (byte)(t.length))
}

type Ciphered interface {
	Marshal() []byte
	UnMarshal([]byte, securityParameters) Ciphered
	Content() []byte
	Mac() []byte
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

func (c GenericStreamCipher) UnMarshal(fragment []byte, params securityParameters) Ciphered {
	c.content = fragment[:len(fragment)-int(params.macAlgorithm.Size())]
	c.MAC = fragment[len(fragment)-int(params.macAlgorithm.Size()):]
	return c
}

func (c GenericStreamCipher) Content() []byte {
	return c.content
}

func (c GenericStreamCipher) Mac() []byte {
	return c.MAC
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

func (c GenericBlockCipher) UnMarshal(fragment []byte, params securityParameters) Ciphered {
	c.IV = fragment[:params.recordIVLength]
	c.padding_length = fragment[len(fragment)-1]
	c.padding = fragment[len(fragment)-1-int(c.padding_length) : len(fragment)-1]
	c.MAC = fragment[len(fragment)-1-int(c.padding_length)-int(params.macAlgorithm.Size()) : len(fragment)-1-int(c.padding_length)]
	c.content = fragment[params.recordIVLength : len(fragment)-1-int(c.padding_length)-int(params.macAlgorithm.Size())]
	return c
}

func (c GenericBlockCipher) Content() []byte {
	return c.content
}

func (c GenericBlockCipher) Mac() []byte {
	return c.MAC
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

func (c GenericAEADCipher) UnMarshal(fragment []byte, params securityParameters) Ciphered {
	c.nonce_explicit = fragment[:params.recordIVLength]
	c.content = fragment[params.recordIVLength:]
	return c
}

func (c GenericAEADCipher) Content() []byte {
	return c.content
}

func (c GenericAEADCipher) Mac() []byte {
	return []byte{}
}
