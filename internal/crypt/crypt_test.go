package crypt

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The stretched keys below were produced by the official Bitwarden CLI for the
// same master key; a wrong HKDF (extract-then-expand) breaks this vector.
func TestStretchMatchesBitwarden(t *testing.T) {
	master := mustHex(t, "555d8329c220720ed18d509d3e1d5580a55271e43782e84a0986df1746d62ab4")
	k := Stretch(master)
	if got := hex.EncodeToString(k.Enc); got != "993da68ff0c712b9b4c784a874b5ddfe259b94d9d7187f4e6aa48ae93c7a6144" {
		t.Fatalf("enc key = %s", got)
	}
	if got := hex.EncodeToString(k.Mac); got != "ba826be0532acb0ebca097ea27b65db018ac2bc2f458c85198cfeeb6433f97ed" {
		t.Fatalf("mac key = %s", got)
	}
}

// RFC 7914 section 11 / common PBKDF2-HMAC-SHA256 vector.
func TestDeriveMasterPBKDF2(t *testing.T) {
	got, err := DeriveMaster("password", "SALT", KDFParams{Type: KDFPBKDF2SHA256, Iterations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" {
		t.Fatalf("master key = %s", hex.EncodeToString(got))
	}
}

func TestDeriveMasterArgon2(t *testing.T) {
	got, err := DeriveMaster("password", "user@example.com", KDFParams{
		Type: KDFArgon2id, Iterations: 2, Memory: 64 * 1024, Parallelism: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("length = %d", len(got))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := Stretch([]byte("0123456789abcdef0123456789abcdef"))
	for _, plain := range []string{"", "hunter2", strings.Repeat("x", 100), "多字节密钥"} {
		enc, err := key.Encrypt([]byte(plain))
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
		}
		if !strings.HasPrefix(enc, "2.") {
			t.Fatalf("unexpected encoding %q", enc)
		}
		got, err := key.DecryptString(enc)
		if err != nil {
			t.Fatalf("decrypt %q: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("round trip = %q, want %q", got, plain)
		}
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	key := Stretch([]byte("0123456789abcdef0123456789abcdef"))
	enc, err := key.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(enc, "|", 3)
	parts[0] = strings.TrimSuffix(parts[0], "A") + "B"
	if _, err := key.Decrypt(strings.Join(parts, "|")); err == nil {
		t.Fatal("tampered ciphertext decrypted without error")
	}
}

func TestDecryptRejectsOtherKey(t *testing.T) {
	key := Stretch([]byte("0123456789abcdef0123456789abcdef"))
	other := Stretch([]byte("ffffffffffffffffffffffffffffffff"))
	enc, err := key.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(enc); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
}

func TestDecryptRejectsMalformed(t *testing.T) {
	key := Stretch([]byte("0123456789abcdef0123456789abcdef"))
	for _, s := range []string{"", "0.abc|def", "2.a|b", "2.!!!|???|&&&"} {
		if _, err := key.Decrypt(s); err == nil {
			t.Fatalf("%q decrypted without error", s)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
