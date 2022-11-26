package dns

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

func verifySignature(message []byte, pubkeyBytes []byte, signature []byte) error {
	pub := decodePublicKey(pubkeyBytes)
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, hashed[:], signature)
}

func decodePublicKey(key []byte) rsa.PublicKey {
	// RFC 3110
	var exponentLen uint16
	var offset uint16
	if key[0] == 0 {
		exponentLen = binary.BigEndian.Uint16(key[1:])
		offset = 3
	} else {
		exponentLen = uint16(key[0])
		offset = 1
	}
	return rsa.PublicKey{
		N: new(big.Int).SetBytes(key[offset+exponentLen:]),
		E: int(new(big.Int).SetBytes(key[offset : offset+exponentLen]).Int64()),
	}
}
