package xchacha20poly1305

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestXChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	aead, _ := Init(key)
	data := make([]byte, 1024)
	io.ReadFull(rand.Reader, data)
	t.Run("random payload", func(t *testing.T) {
		encrypted := aead.Seal(data)
		decrypted, err := aead.Open(encrypted)
		if err != nil {
			t.Errorf("error : XChaCha20Poly1305.Seal() %v", err)
			return
		}
		if !reflect.DeepEqual(data, decrypted) {
			t.Errorf("XChaCha20Poly1305 = %v, want %v", data, decrypted)
		}
	})
}
