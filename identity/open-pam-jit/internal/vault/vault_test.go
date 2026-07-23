package vault

import (
	"bytes"
	"testing"
)

func TestPBKDF2Deterministic(t *testing.T) {
	a := PBKDF2([]byte("pw"), []byte("salt"), 1000, 32)
	b := PBKDF2([]byte("pw"), []byte("salt"), 1000, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("PBKDF2 not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(a))
	}
	c := PBKDF2([]byte("pw"), []byte("different"), 1000, 32)
	if bytes.Equal(a, c) {
		t.Fatal("different salt should produce different key")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	v, err := New("passphrase", []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt([]byte("super-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if enc == "super-secret" {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := v.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "super-secret" {
		t.Fatalf("roundtrip mismatch: %s", pt)
	}
}

func TestVaultStore(t *testing.T) {
	v, _ := New("pw", []byte("salt"))
	if err := v.Put("db-password", "hunter2"); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get("db-password")
	if err != nil || got != "hunter2" {
		t.Fatalf("expected hunter2, got %q err=%v", got, err)
	}
	v.Delete("db-password")
	if _, err := v.Get("db-password"); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestWrongKeyFails(t *testing.T) {
	v1, _ := New("right", []byte("salt"))
	enc, _ := v1.Encrypt([]byte("data"))
	v2, _ := New("wrong", []byte("salt"))
	if _, err := v2.Decrypt(enc); err == nil {
		t.Fatal("decryption with wrong key should fail")
	}
}
