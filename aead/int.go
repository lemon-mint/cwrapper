package aead

type AEAD interface {
	Seal(data []byte) []byte
	Open(data []byte) ([]byte, error)
}
