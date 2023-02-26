package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

const (
	NonceSize = 24
	KeySize   = 32
)

type SecretBox struct {
	key [KeySize]byte
}

func (b *SecretBox) Encrypt(plaintext []byte) (ciphertext []byte) {
	var nonce [NonceSize]byte

	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	ciphertext = secretbox.Seal(nonce[:], plaintext, &nonce, &b.key)
	return
}

func (b *SecretBox) Decrypt(ciphertext []byte) (plaintext []byte, ok bool) {
	var nonce [NonceSize]byte

	copy(nonce[:], ciphertext[:NonceSize])

	plaintext, ok = secretbox.Open(nil, ciphertext[NonceSize:], &nonce, &b.key)
	return
}

func isZero(slice []byte) bool {
	c := 0x01

	for _, b := range slice {
		c &= subtle.ConstantTimeByteEq(b, 0)
	}
	return c == 0x01
}

func NewSecretBox(key [32]byte) SecretBox {
	if isZero(key[:]) {
		panic("Cannot initialize secretbox with zero key!")
	}

	b := SecretBox{
		key: key,
	}

	return b
}
