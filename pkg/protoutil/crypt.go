package protoutil

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	cryptpb "github.com/pomerium/pomerium/pkg/grpc/crypt"
)

// Key is a Curve25519 private or public key.
type Key struct {
	ID   string
	Data [32]byte
}

// public returns the private key's public key.
func (key Key) public() Key {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &key.Data)
	return Key{ID: key.ID, Data: publicKey}
}

type KeySource interface {
	GetKey(id string) (Key, error)
}

type KeySourceFunc func(id string) (Key, error)

func (src KeySourceFunc) GetKey(id string) (Key, error) {
	return src(id)
}

type Encryptor struct {
	key         Key
	rotateEvery time.Duration

	sync.RWMutex
	nextRotate time.Time
	dekBytes   [chacha20poly1305.KeySize]byte
	dek        cipher.AEAD
}

// NewEncryptor returns a new protobuf Encryptor.
func NewEncryptor(key Key) *Encryptor {
	return &Encryptor{
		key:         key,
		rotateEvery: time.Hour,
	}
}

func (enc *Encryptor) getDataEncryptionKey() ([chacha20poly1305.KeySize]byte, cipher.AEAD, error) {
	enc.RLock()
	dekBytes, dek := enc.dekBytes, enc.dek
	needsNewKey := enc.dek == nil || time.Now().Before(enc.nextRotate)
	enc.RUnlock()

	if !needsNewKey {
		return dekBytes, dek, nil
	}

	enc.Lock()
	defer enc.Unlock()

	needsNewKey = enc.dek == nil || time.Now().Before(enc.nextRotate)
	if needsNewKey {
		_, err := io.ReadFull(rand.Reader, enc.dekBytes[:])
		if err != nil {
			return dekBytes, nil, err
		}

		enc.dek, err = chacha20poly1305.NewX(enc.dekBytes[:])
		if err != nil {
			return dekBytes, nil, err
		}

		enc.nextRotate = time.Now().Add(enc.rotateEvery)
	}

	return enc.dekBytes, enc.dek, nil
}

// Seal encrypts a protobuf message.
func (enc *Encryptor) Seal(msg proto.Message) (*cryptpb.SealedMessage, error) {
	dekBytes, dek, err := enc.getDataEncryptionKey()
	if err != nil {
		return nil, err
	}
	dekSealedBytes, err := box.SealAnonymous(nil, dekBytes[:], &enc.key.Data, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("protoutil: error encrypting data-encryption-key: %w", err)
	}

	sealed, err := Transform(msg, func(fd protoreflect.FieldDescriptor, v protoreflect.Value) (protoreflect.Value, error) {
		switch fd.Kind() {
		case protoreflect.BytesKind:
			bs := cryptutil.Encrypt(dek, v.Bytes(), nil)
			return protoreflect.ValueOfBytes(bs), nil
		case protoreflect.StringKind:
			bs := cryptutil.Encrypt(dek, []byte(v.String()), nil)
			raw := base64.StdEncoding.EncodeToString(bs)
			return protoreflect.ValueOfString(raw), nil
		}
		return v, nil
	})
	if err != nil {
		return nil, fmt.Errorf("protoutil: error encrypting data: %w", err)
	}

	sealedAny, err := anypb.New(sealed)
	if err != nil {
		return nil, fmt.Errorf("protoutil: error marshaling encrypted data: %w", err)
	}

	return &cryptpb.SealedMessage{
		KeyId:             enc.key.ID,
		DataEncryptionKey: dekSealedBytes,
		Data:              sealedAny,
	}, nil
}

type Decryptor struct {
	keySource KeySource
}

// NewDecryptor returns a new protobuf Decryptor.
func NewDecryptor(keySource KeySource) *Decryptor {
	return &Decryptor{
		keySource: keySource,
	}
}

// Open decrypts an encrypted protobuf message.
func (dec *Decryptor) Open(src *cryptpb.SealedMessage) (proto.Message, error) {
	kekPrivate, err := dec.keySource.GetKey(src.GetKeyId())
	if err != nil {
		return nil, fmt.Errorf("protoutil: error getting key-encryption-key (%s): %w", src.GetKeyId(), err)
	}
	kekPublic := kekPrivate.public()

	dekRaw, ok := box.OpenAnonymous(nil, src.DataEncryptionKey, &kekPublic.Data, &kekPrivate.Data)
	if !ok {
		return nil, fmt.Errorf("protoutil: error decrypting data-encryption-key")
	}
	dek, err := chacha20poly1305.NewX(dekRaw)
	if err != nil {
		return nil, fmt.Errorf("protoutil: invalid data-encryption-key: %w", err)
	}

	sealed, err := src.Data.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("protoutil: error unmarshaling encrypted data: %w", err)
	}

	opened, err := Transform(sealed, func(fd protoreflect.FieldDescriptor, v protoreflect.Value) (protoreflect.Value, error) {
		switch fd.Kind() {
		case protoreflect.BytesKind:
			bs, err := cryptutil.Decrypt(dek, v.Bytes(), nil)
			if err != nil {
				return v, err
			}
			return protoreflect.ValueOfBytes(bs), nil
		case protoreflect.StringKind:
			raw, err := base64.StdEncoding.DecodeString(v.String())
			if err != nil {
				return v, err
			}
			bs, err := cryptutil.Decrypt(dek, raw, nil)
			if err != nil {
				return v, err
			}
			return protoreflect.ValueOfString(string(bs)), nil
		}
		return v, nil
	})
	if err != nil {
		return nil, fmt.Errorf("protoutil: error decrypting encrypted data: %w", err)
	}

	return opened, nil
}
