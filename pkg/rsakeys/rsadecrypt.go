package rsakeys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// RSADecryptor handles RSA decryption operations
type RSADecryptor struct {
	EncryptedAESKeyFile string
	PrivateKeyFile      string
}

// NewRSADecryptor initializes a new RSADecryptor
func NewRSADecryptor(encryptedAESKeyFile, privateKeyFile string) *RSADecryptor {
	return &RSADecryptor{
		EncryptedAESKeyFile: encryptedAESKeyFile,
		PrivateKeyFile:      privateKeyFile,
	}
}

// ReadFile reads the contents of a file and returns it as a byte slice
func (rd *RSADecryptor) ReadFile(filePath string) []byte {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("[-] Error reading file %s: %v", filePath, err)
	}
	return data
}

// DecodePrivateKeyPEM decodes the PEM block from the private key file
func (rd *RSADecryptor) DecodePrivateKeyPEM(privateKeyPEM []byte) *pem.Block {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalln("[-] Error decoding private key PEM block")
	}
	return block
}

// ParsePrivateKey parses the RSA private key from a PEM block
func (rd *RSADecryptor) ParsePrivateKey(block *pem.Block) *rsa.PrivateKey {
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalln("[-] Error parsing RSA private key:", err)
	}
	return privateKey
}

// DecryptAESKey decrypts the AES key using the RSA private key
func (rd *RSADecryptor) DecryptAESKey(privateKey *rsa.PrivateKey, encryptedAESKey []byte) []byte {
	decryptedKey, err := rsa.DecryptPKCS1v15(nil, privateKey, encryptedAESKey)
	if err != nil {
		log.Fatalln("[-] Error decrypting AES key:", err)
	}
	return decryptedKey
}

// DecryptAndLogAESKey orchestrates the decryption process and logs the decrypted AES key
func (rd *RSADecryptor) DecryptAndLogAESKey() {
	encryptedAESKey := rd.ReadFile(rd.EncryptedAESKeyFile)
	privateKeyPEM := rd.ReadFile(rd.PrivateKeyFile)
	block := rd.DecodePrivateKeyPEM(privateKeyPEM)
	privateKey := rd.ParsePrivateKey(block)
	decryptedAESKey := rd.DecryptAESKey(privateKey, encryptedAESKey)

	// Log the decrypted AES key in hexadecimal format
	log.Printf("[+] Decrypted AES key: %x\n", decryptedAESKey)
}

// DecryptAndLogAESKey orchestrates the decryption process and logs the decrypted AES key
func (rd *RSADecryptor) DecryptAndParseAESKey() []byte {
	encryptedAESKey := rd.ReadFile(rd.EncryptedAESKeyFile)
	privateKeyPEM := rd.ReadFile(rd.PrivateKeyFile)
	block := rd.DecodePrivateKeyPEM(privateKeyPEM)
	privateKey := rd.ParsePrivateKey(block)
	decryptedAESKey := rd.DecryptAESKey(privateKey, encryptedAESKey)

	// Return the decrypted AES key in hexadecimal format
	return decryptedAESKey
}

// Returns the unencrypted AES Key
func UnencryptedAESKey() []byte {
	// Initialize RSADecryptor to decrypt AES encrypted key
	rsaDecryptor := NewRSADecryptor(EncryptedAESBinFile, privateKeyPEM)
	return rsaDecryptor.DecryptAndParseAESKey()
}

func DecrypteAESEncyrptedKey() {
	// Initialize RSADecryptor to decrypt AES encrypted key
	rsaDecryptor := NewRSADecryptor(EncryptedAESBinFile, privateKeyPEM)
	// Decrypt the AES key and log it
	rsaDecryptor.DecryptAndLogAESKey()
}
