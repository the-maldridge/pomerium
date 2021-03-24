package cryptutil

const BoxKeySize = 32

type AnonymousSealedBox struct {
	ephemeralPublicKey, ephemeralPrivateKey [BoxKeySize]byte
	recipientKey [BoxKeySize]byte
}

func NewAnonymousSealedBox
