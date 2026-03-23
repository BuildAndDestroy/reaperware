package aeskeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
)

// FileManager manages file paths and operations for encryption and decryption
type FileManager struct {
	InputFilePath     string
	EncryptedFilePath string
	DecryptedFilePath string
}

// Encryptor handles AES encryption operations
type Encryptor struct {
	Key               []byte
	FileManager       FileManager
	MaxPlaintextBytes int64 // 0 = unlimited; encrypt refuses larger plaintext after stat
}

// NewEncryptor initializes the Encryptor with the AES key and file paths
func NewEncryptor(key []byte, inputFilePath, encryptedFilePath, decryptedFilePath string) *Encryptor {
	return &Encryptor{
		Key: key,
		FileManager: FileManager{
			InputFilePath:     inputFilePath,
			EncryptedFilePath: encryptedFilePath,
			DecryptedFilePath: decryptedFilePath,
		},
	}
}

// validateKey ensures the AES key length is valid
func (e *Encryptor) validateKey() error {
	if len(e.Key) != 16 && len(e.Key) != 24 && len(e.Key) != 32 {
		return fmt.Errorf("invalid AES key length")
	}
	return nil
}

// readInputFile reads the contents of the input file
func (e *Encryptor) readInputFile(id int) ([]byte, error) {
	data, err := os.ReadFile(e.FileManager.InputFilePath)
	if err != nil {
		return nil, fmt.Errorf("[worker %d] read input file: %w", id, err)
	}
	return data, nil
}

// createCipherBlock creates a new AES cipher block
func (e *Encryptor) createCipherBlock() (cipher.Block, error) {
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher block: %w", err)
	}
	return block, nil
}

// createGCM creates a GCM cipher for AES
func (e *Encryptor) createGCM(block cipher.Block) (cipher.AEAD, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM cipher: %w", err)
	}
	return aesGCM, nil
}

// generateNonce generates a random nonce
func (e *Encryptor) generateNonce(aesGCM cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// encryptData encrypts plaintext using AES-GCM
func (e *Encryptor) encryptData(aesGCM cipher.AEAD, nonce, plaintext []byte) []byte {
	return aesGCM.Seal(nil, nonce, plaintext, nil)
}

// writeToFile writes data to a specified file
func (e *Encryptor) writeToFile(filePath string, data []byte, id int) error {
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("[worker %d] write file %s: %w", id, filePath, err)
	}
	log.Printf("[+] [Worker %d] Successfully wrote to file: %s\n", id, filePath)
	return nil
}

// Encrypt encrypts the input file and writes the result to the encrypted file
func (e *Encryptor) Encrypt(id int) error {
	if err := e.validateKey(); err != nil {
		return err
	}

	if e.MaxPlaintextBytes > 0 {
		st, err := os.Stat(e.FileManager.InputFilePath)
		if err != nil {
			return fmt.Errorf("[worker %d] stat input file: %w", id, err)
		}
		if st.Size() > e.MaxPlaintextBytes {
			return fmt.Errorf("[worker %d] file too large: %d > max %d", id, st.Size(), e.MaxPlaintextBytes)
		}
	}

	// Read plaintext from input file
	plaintext, err := e.readInputFile(id)
	if err != nil {
		return err
	}

	// Create AES cipher block and GCM
	block, err := e.createCipherBlock()
	if err != nil {
		return err
	}
	aesGCM, err := e.createGCM(block)
	if err != nil {
		return err
	}

	// Generate nonce and encrypt plaintext
	nonce, err := e.generateNonce(aesGCM)
	if err != nil {
		return err
	}
	ciphertext := e.encryptData(aesGCM, nonce, plaintext)

	// Combine nonce and ciphertext
	finalOutput := append(nonce, ciphertext...)

	// Write encrypted data to the encrypted file
	if err := e.writeToFile(e.FileManager.EncryptedFilePath, finalOutput, id); err != nil {
		return err
	}

	return nil
}

// Decrypt method for the Encryptor
func (e *Encryptor) Decrypt(id int) {
	// Open the encrypted file for reading
	encryptedFile, err := os.Open(e.FileManager.InputFilePath)
	if err != nil {
		log.Fatalf("[-] [Worker %d] Error opening encrypted file: %v\n", id, err)
	}
	defer encryptedFile.Close()

	// Open the output file for writing decrypted data
	decryptedFile, err := os.Create(e.FileManager.DecryptedFilePath)
	if err != nil {
		log.Fatalf("[-] [Worker %d] Error creating decrypted file: %v\n", id, err)
	}
	defer decryptedFile.Close()

	// Read the IV from the start of the encrypted file
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(encryptedFile, iv); err != nil {
		log.Fatalf("[-] [Worker %d] Error reading IV from encrypted file: %v\n", id, err)
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		log.Fatalf("[-] [Worker %d] Error creating AES cipher: %v\n", id, err)
	}

	// Create a stream for decryption
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt the file content
	reader := &cipher.StreamReader{S: stream, R: encryptedFile}
	if _, err := io.Copy(decryptedFile, reader); err != nil {
		log.Fatalf("[-] [Worker %d] Error decrypting file: %v\n", id, err)
	}

	log.Printf("[+] [Worker %d] File decrypted successfully: %s\n", id, e.FileManager.DecryptedFilePath)
}
