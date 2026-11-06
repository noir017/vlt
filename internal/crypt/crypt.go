// Package crypt implements the subset of the Bitwarden crypto used by
// Vaultwarden: key derivation from the master password, HKDF expansion into
// an encryption/MAC key pair, and the EncString encoding used on the wire.
package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KDF identifiers used by Bitwarden.
const (
	KDFPBKDF2SHA256 = 0
	KDFArgon2id     = 1
)

// KDFParams describes how the server expects the master key to be derived.
type KDFParams struct {
	Type        int
	Iterations  int
	Memory      int
	Parallelism int
}

// Key is a stretched master key: 32 bytes for AES-256 and 32 bytes for HMAC.
type Key struct {
	Enc []byte
	Mac []byte
}

// NormalizeEmail returns the salt form used by every Bitwarden client.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// DeriveMaster derives the 32-byte master key from the master password.
func DeriveMaster(password, email string, p KDFParams) ([]byte, error) {
	salt := []byte(NormalizeEmail(email))
	switch p.Type {
	case KDFPBKDF2SHA256:
		if p.Iterations <= 0 {
			return nil, fmt.Errorf("invalid PBKDF2 iteration count %d", p.Iterations)
		}
		return pbkdf2.Key([]byte(password), salt, p.Iterations, 32, sha256.New), nil
	case KDFArgon2id:
		if p.Iterations <= 0 || p.Memory <= 0 || p.Parallelism <= 0 {
			return nil, fmt.Errorf("invalid Argon2 parameters (%d iterations, %d KiB, %d lanes)", p.Iterations, p.Memory, p.Parallelism)
		}
		return argon2.IDKey([]byte(password), salt, uint32(p.Iterations), uint32(p.Memory), uint8(p.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", p.Type)
	}
}

// HashMaster produces the value sent to /identity/connect/token.
func HashMaster(masterKey []byte, password string) string {
	sum := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(sum)
}

// Stretch expands the master key into the enc/mac pair. Bitwarden uses
// HKDF-Expand only (RFC 5869 section 3), with the master key as the PRK —
// running the full extract-then-expand gives different bytes and a vault that
// can never be decrypted.
func Stretch(masterKey []byte) *Key {
	return &Key{
		Enc: hmacSum(masterKey, []byte("enc\x01")),
		Mac: hmacSum(masterKey, []byte("mac\x01")),
	}
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Encrypt encodes plaintext as a Bitwarden EncString of type 2.
func (k *Key) Encrypt(plain []byte) (string, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k.Enc)
	if err != nil {
		return "", err
	}
	padded := pad(plain)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, k.Mac)
	mac.Write(iv)
	mac.Write(ct)

	return fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	), nil
}

// Decrypt decodes an EncString of type 2 and verifies its MAC first.
func (k *Key) Decrypt(s string) ([]byte, error) {
	iv, ct, tag, err := split(s)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, k.Mac)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, errors.New("encrypted payload failed integrity check")
	}
	block, err := aes.NewCipher(k.Enc)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 || len(ct) == 0 {
		return nil, errors.New("encrypted payload has invalid length")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return unpad(out)
}

// DecryptString is Decrypt with a UTF-8 string result.
func (k *Key) DecryptString(s string) (string, error) {
	b, err := k.Decrypt(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func split(s string) (iv, ct, tag []byte, err error) {
	if !strings.HasPrefix(s, "2.") {
		return nil, nil, nil, fmt.Errorf("unsupported encrypted value (only type 2 is supported)")
	}
	parts := strings.Split(s[2:], "|")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("malformed encrypted value")
	}
	if iv, err = base64.StdEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, errors.New("malformed encrypted value (iv)")
	}
	if ct, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, errors.New("malformed encrypted value (data)")
	}
	if tag, err = base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return nil, nil, nil, errors.New("malformed encrypted value (mac)")
	}
	if len(iv) != aes.BlockSize {
		return nil, nil, nil, errors.New("malformed encrypted value (iv length)")
	}
	return iv, ct, tag, nil
}

func pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty plaintext")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("invalid padding")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-n], nil
}
