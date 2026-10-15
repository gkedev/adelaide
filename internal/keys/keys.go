// Package keys persists signing keys, so the public keys a server
// publishes survive restarts.
package keys

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	aauth "github.com/aauth-dev/aauth-go"
)

// LoadOrCreate returns the key in dir/name.pem, generating one with alg
// (aauth.AlgEd25519 or aauth.AlgES256) when the file does not exist. An
// empty dir generates a fresh key every time.
func LoadOrCreate(dir, name, alg string) (crypto.Signer, error) {
	if dir == "" {
		return aauth.GenerateKey(alg)
	}
	path := filepath.Join(dir, name+".pem")
	b, err := os.ReadFile(path)
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("keys: %s is not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: %s: %w", path, err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("keys: %s is not a signing key", path)
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := aauth.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}
