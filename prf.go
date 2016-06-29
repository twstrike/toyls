package toyls

import (
	"crypto/hmac"
	"crypto/sha256"
)

func prf(dst, secret []byte, label string, seed []byte) {
	label_b := []byte(label)
	p_hash(dst, secret, append(label_b, seed...))
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
