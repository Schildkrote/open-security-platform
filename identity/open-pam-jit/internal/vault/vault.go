// Package vault is an encrypted secrets store using AES-256-GCM with a key
// derived from a passphrase via PBKDF2-HMAC-SHA256 (all standard library).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
)

// PBKDF2 derives a key from a password and salt (RFC 2898) using HMAC-SHA256.
func PBKDF2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		t := prf.Sum(nil)
		u := append([]byte(nil), t...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// Vault encrypts and stores secrets in memory.
type Vault struct {
	mu   sync.RWMutex
	aead cipher.AEAD
	data map[string]string // name -> base64(nonce||ciphertext)
}

// New derives a key from the passphrase and returns a ready Vault.
func New(passphrase string, salt []byte) (*Vault, error) {
	key := PBKDF2([]byte(passphrase), salt, 100_000, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, data: map[string]string{}}, nil
}

// Encrypt returns base64(nonce||ciphertext).
func (v *Vault) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := v.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt.
func (v *Vault) Decrypt(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	ns := v.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return v.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// Put encrypts and stores a secret.
func (v *Vault) Put(name, secret string) error {
	enc, err := v.Encrypt([]byte(secret))
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data[name] = enc
	return nil
}

// Get decrypts and returns a secret.
func (v *Vault) Get(name string) (string, error) {
	v.mu.RLock()
	enc, ok := v.data[name]
	v.mu.RUnlock()
	if !ok {
		return "", errors.New("secret not found")
	}
	pt, err := v.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Delete removes a secret.
func (v *Vault) Delete(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.data, name)
}
