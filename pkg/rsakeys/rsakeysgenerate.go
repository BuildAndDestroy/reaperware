package rsakeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"
)

const (
	EncryptedAESBinFile string = "encrypted_aes_key.bin"
	privateKeyPEM       string = "private_key.pem"
	publicKeyPEM        string = "public_key.pem"
)

// KeyManager manages RSA key generation and storage
type KeyManager struct {
	KeySize        int
	PrivateKeyPath string
	PublicKeyPath  string
}

// NewKeyManager initializes a new KeyManager
func NewKeyManager(keySize int, privateKeyPath, publicKeyPath string) *KeyManager {
	return &KeyManager{
		KeySize:        keySize,
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
	}
}

// GeneratePrivateKey generates an RSA private key
func (km *KeyManager) GeneratePrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, km.KeySize)
	if err != nil {
		log.Fatalln("[-] Error generating RSA private key:", err)
	}
	return privateKey
}

// EncodePrivateKey encodes the RSA private key into PEM format
func (km *KeyManager) EncodePrivateKey(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// SavePrivateKey saves the private key to the specified file
func (km *KeyManager) SavePrivateKey(privateKeyPEM []byte) {
	err := os.WriteFile(km.PrivateKeyPath, privateKeyPEM, 0600)
	if err != nil {
		log.Fatalln("[-] Error saving private key to file:", err)
	}
	log.Println("[+] Private key saved to", km.PrivateKeyPath)
}

// ExtractPublicKey extracts the public key from the private key
func (km *KeyManager) ExtractPublicKey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	return &privateKey.PublicKey
}

// EncodePublicKey encodes the RSA public key into PEM format
func (km *KeyManager) EncodePublicKey(publicKey *rsa.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalln("[-] Error marshaling public key:", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
}

// SavePublicKey saves the public key to the specified file
func (km *KeyManager) SavePublicKey(publicKeyPEM []byte) {
	err := os.WriteFile(km.PublicKeyPath, publicKeyPEM, 0644)
	if err != nil {
		log.Fatalln("[-] Error saving public key to file:", err)
	}
	log.Println("[+] Public key saved to", km.PublicKeyPath)
}

// GenerateAndSaveKeys generates both private and public keys and saves them to memory
func (km *KeyManager) GenerateAndSaveKeysToMemory() ([]byte, []byte) {
	privateKey := km.GeneratePrivateKey()

	// Encode private key
	privateKeyPEM := km.EncodePrivateKey(privateKey)

	// Extract, encode, and save public key
	publicKey := km.ExtractPublicKey(privateKey)
	publicKeyPEM := km.EncodePublicKey(publicKey)

	return privateKeyPEM, publicKeyPEM
}

// Save private key
func (km *KeyManager) WritePrivateKeyToFile(privateKeyPEM []byte) {
	km.SavePrivateKey(privateKeyPEM)
}

// GenerateAndSaveKeys generates both private and public keys and saves them to files
func (km *KeyManager) GenerateAndSaveKeys() {
	privateKey := km.GeneratePrivateKey()

	// Encode and save private key
	privateKeyPEM := km.EncodePrivateKey(privateKey)
	km.SavePrivateKey(privateKeyPEM)

	// Extract, encode, and save public key
	publicKey := km.ExtractPublicKey(privateKey)
	publicKeyPEM := km.EncodePublicKey(publicKey)
	km.SavePublicKey(publicKeyPEM)
}

func CreateRSAKeys() ([]byte, []byte) {
	// RSA private and public keys
	initRSAStart := time.Now()
	rsaKeyManager := NewKeyManager(4096, privateKeyPEM, publicKeyPEM)
	rsaKeyManager.GenerateAndSaveKeys()
	rsaPrivateKey, rsaPublicKey := rsaKeyManager.GenerateAndSaveKeysToMemory()
	rsaKeyManager.WritePrivateKeyToFile(rsaPrivateKey)
	elapsedRSA := time.Since(initRSAStart)
	log.Println("[*] Time RSA keys have taken to create:", elapsedRSA)
	return rsaPrivateKey, rsaPublicKey
}
