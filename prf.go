package toyls

import (
	"crypto/hmac"
	"crypto/sha256"
)

const keyExpansionLabel = "key expansion"

func prf(dst, secret []byte, label string, seed []byte) {
	label_b := []byte(label)
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label_b)
	copy(labelAndSeed[len(label_b):], seed)
	p_hash(dst, secret, labelAndSeed)
}

func p_hash(result, secret, seed []byte) {
	size := 0
	h := hmac.New(sha256.New, secret)
	h.Write(seed)
	a := h.Sum(nil)
	for size < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		currentHMAC := h.Sum(nil)
		currentSize := len(currentHMAC)
		if (size + currentSize) > len(result) {
			currentSize = len(result) - size
		}
		copy(result[size:size+currentSize], currentHMAC)
		size += currentSize

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func keysFromMasterSecret(params securityParameters) *writeParams {
	seed := make([]byte, 0, len(params.server_random)+len(params.client_random))
	seed = append(seed, params.server_random[:]...)
	seed = append(seed, params.client_random[:]...)

	n := 2*params.mac_key_length + 2*params.enc_key_length + 2*params.fixed_iv_length
	keyMaterial := make([]byte, n)
	prf(keyMaterial, params.master_secret[:], keyExpansionLabel, seed)

	w := new(writeParams)
	w.clientMAC = keyMaterial[:params.mac_key_length]
	keyMaterial = keyMaterial[params.mac_key_length:]

	w.serverMAC = keyMaterial[:params.mac_key_length]
	keyMaterial = keyMaterial[params.mac_key_length:]

	w.clientKey = keyMaterial[:params.enc_key_length]
	keyMaterial = keyMaterial[params.enc_key_length:]

	w.serverKey = keyMaterial[:params.enc_key_length]
	keyMaterial = keyMaterial[params.enc_key_length:]

	w.clientIV = keyMaterial[:params.fixed_iv_length]
	keyMaterial = keyMaterial[params.fixed_iv_length:]

	w.serverIV = keyMaterial[:params.fixed_iv_length]
	return w
}
