package xchacha20poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type XChaCha20Poly1305 struct {
	key  []byte
	aead cipher.AEAD
}

func Init(key []byte) (*XChaCha20Poly1305, error) {
	h := blake3.New()
	h.Write(key)
	x := new(XChaCha20Poly1305)
	x.key = h.Sum(nil)
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	x.aead = a
	return x, nil
}

func (x *XChaCha20Poly1305) Seal(data []byte) []byte {
	buf := make([]byte, 24+len(data)+x.aead.Overhead())
	io.ReadFull(rand.Reader, buf[:24])
	encrypted := x.aead.Seal(nil, buf[:24], data, nil)
	copy(buf[24:], encrypted)
	return buf
}

func (x *XChaCha20Poly1305) Open(data []byte) ([]byte, error) {
	return x.aead.Open(nil, data[:24], data[24:], nil)
}
