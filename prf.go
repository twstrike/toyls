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
	seed := make([]byte, 0, len(params.serverRandom)+len(params.clientRandom))
	seed = append(seed, params.serverRandom[:]...)
	seed = append(seed, params.clientRandom[:]...)

	n := 2*params.macKeyLength + 2*params.encKeyLength + 2*params.fixedIVLength
	keyMaterial := make([]byte, n)
	prf(keyMaterial, params.masterSecret[:], keyExpansionLabel, seed)

	w := new(writeParams)
	w.clientMAC = keyMaterial[:params.macKeyLength]
	keyMaterial = keyMaterial[params.macKeyLength:]

	w.serverMAC = keyMaterial[:params.macKeyLength]
	keyMaterial = keyMaterial[params.macKeyLength:]

	w.clientKey = keyMaterial[:params.encKeyLength]
	keyMaterial = keyMaterial[params.encKeyLength:]

	w.serverKey = keyMaterial[:params.encKeyLength]
	keyMaterial = keyMaterial[params.encKeyLength:]

	w.clientIV = keyMaterial[:params.fixedIVLength]
	keyMaterial = keyMaterial[params.fixedIVLength:]

	w.serverIV = keyMaterial[:params.fixedIVLength]
	return w
}
