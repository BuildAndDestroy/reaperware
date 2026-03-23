package aeskeys

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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
func NewAESDecryptor(aesKey []byte, encryptedFilePath string) (*AESDecryptor, error) {
	// Check if AES key length is valid
	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return nil, fmt.Errorf("invalid AES key length")
	}

	// Read encrypted data from file
	encryptedData, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		return nil, fmt.Errorf("read encrypted file: %w", err)
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	// Create AES-GCM instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}

	// Initialize the AESDecryptor struct
	return &AESDecryptor{
		AESKey:        aesKey,
		EncryptedData: encryptedData,
		AESCipher:     block,
		AESGCM:        aesGCM,
	}, nil
}

// ExtractNonceAndCiphertext extracts the nonce and ciphertext from the encrypted data
func (d *AESDecryptor) ExtractNonceAndCiphertext() error {
	nonceSize := d.AESGCM.NonceSize()
	if len(d.EncryptedData) < nonceSize {
		return fmt.Errorf("invalid encrypted data")
	}
	d.Nonce = d.EncryptedData[:nonceSize]
	d.Ciphertext = d.EncryptedData[nonceSize:]
	return nil
}

// Decrypt decrypts the ciphertext using the AES key and returns the plaintext
func (d *AESDecryptor) Decrypt() ([]byte, error) {
	plaintext, err := d.AESGCM.Open(nil, d.Nonce, d.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt file: %w", err)
	}
	return plaintext, nil
}

// WriteToFile writes the decrypted content to a new file
func (d *AESDecryptor) WriteToFile(decryptedFilePath string, plaintext []byte, id int) error {
	err := os.WriteFile(decryptedFilePath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("[worker %d] write decrypted file: %w", id, err)
	}
	log.Printf("[+] [Worker %d] File decrypted successfully: %s\n", id, decryptedFilePath)
	return nil
}

// DecryptFile orchestrates the AES decryption process for a file
func (d *AESDecryptor) DecryptFile(decryptedFilePath string, id int) error {
	if err := d.ExtractNonceAndCiphertext(); err != nil {
		return err
	}
	plaintext, err := d.Decrypt()
	if err != nil {
		return err
	}
	if err := d.WriteToFile(decryptedFilePath, plaintext, id); err != nil {
		return err
	}
	return nil
}
