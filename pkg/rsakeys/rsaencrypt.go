package rsakeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// RSAEncryptor handles RSA public key encryption
type RSAEncryptor struct {
	EncryptedAESKeyFile string
}

// NewRSAEncryptor initializes a new RSAEncryptor
func NewRSAEncryptor(encryptedAESKeyFile string) *RSAEncryptor {
	return &RSAEncryptor{
		EncryptedAESKeyFile: encryptedAESKeyFile,
	}
}

// DecodePublicKey decodes a PEM-encoded public RSA key
func (re *RSAEncryptor) DecodePublicKey(pubKeyPEM []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatalln("[-] Error decoding public key PEM block")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalln("[-] Error parsing public RSA key:", err)
	}

	rsaPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalln("[-] Not a valid RSA public key")
	}

	return rsaPublicKey
}

// EncryptAESKey encrypts the AES key using the provided RSA public key
func (re *RSAEncryptor) EncryptAESKey(publicKey *rsa.PublicKey, aesKey []byte) []byte {
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
	if err != nil {
		log.Fatalln("[-] Error encrypting AES key:", err)
	}
	return encryptedKey
}

// SaveEncryptedAESKey saves the encrypted AES key to a file
func (re *RSAEncryptor) SaveEncryptedAESKey(encryptedKey []byte) {
	err := os.WriteFile(re.EncryptedAESKeyFile, encryptedKey, 0644)
	if err != nil {
		log.Fatalln("[-] Error saving encrypted AES key to file:", err)
	}
	log.Println("[+] Encrypted AES key saved to", re.EncryptedAESKeyFile)
}

// EncryptAndSaveAESKey encrypts the AES key using a PEM-encoded RSA public key and saves it
func (re *RSAEncryptor) EncryptAndSaveAESKey(pubKeyPEM []byte, aesKey []byte) {
	rsaPublicKey := re.DecodePublicKey(pubKeyPEM)
	encryptedAESKey := re.EncryptAESKey(rsaPublicKey, aesKey)
	re.SaveEncryptedAESKey(encryptedAESKey)
}
