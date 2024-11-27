package aeskeys

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"os"
)

type AESDecryptor struct {
	AESKey        []byte
	EncryptedData []byte
	AESCipher     cipher.Block
	AESGCM        cipher.AEAD
	Nonce         []byte
	Ciphertext    []byte
}

// NewAESDecryptor initializes the AESDecryptor struct with the AES key and reads the encrypted file
func NewAESDecryptor(aesKey []byte, encryptedFilePath string) *AESDecryptor {
	// Check if AES key length is valid
	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		log.Fatalln("[-] Invalid AES key length")
	}

	// Read encrypted data from file
	encryptedData, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		log.Fatalln("[-] Error reading encrypted file:", err)
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatalln("[-] Error creating AES cipher:", err)
	}

	// Create AES-GCM instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalln("[-] Error creating AES-GCM:", err)
	}

	// Initialize the AESDecryptor struct
	return &AESDecryptor{
		AESKey:        aesKey,
		EncryptedData: encryptedData,
		AESCipher:     block,
		AESGCM:        aesGCM,
	}
}

// ExtractNonceAndCiphertext extracts the nonce and ciphertext from the encrypted data
func (d *AESDecryptor) ExtractNonceAndCiphertext() {
	nonceSize := d.AESGCM.NonceSize()
	if len(d.EncryptedData) < nonceSize {
		log.Fatalln("[-] Invalid encrypted data")
	}
	d.Nonce = d.EncryptedData[:nonceSize]
	d.Ciphertext = d.EncryptedData[nonceSize:]
}

// Decrypt decrypts the ciphertext using the AES key and returns the plaintext
func (d *AESDecryptor) Decrypt() []byte {
	plaintext, err := d.AESGCM.Open(nil, d.Nonce, d.Ciphertext, nil)
	if err != nil {
		log.Println("[-] Error decrypting file:", err)
	}
	return plaintext
}

// WriteToFile writes the decrypted content to a new file
func (d *AESDecryptor) WriteToFile(decryptedFilePath string, plaintext []byte, id int) {
	err := os.WriteFile(decryptedFilePath, plaintext, 0644)
	if err != nil {
		log.Printf("[-] [Worker %d] Error writing decrypted file: %s\n", id, err)
	}
	log.Printf("[+] [Worker %d] File decrypted successfully: %s\n", id, decryptedFilePath)
}

// DecryptFile orchestrates the AES decryption process for a file
func (d *AESDecryptor) DecryptFile(decryptedFilePath string, id int) {
	d.ExtractNonceAndCiphertext()
	plaintext := d.Decrypt()
	d.WriteToFile(decryptedFilePath, plaintext, id)
}
