package aeskeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	Key         []byte
	FileManager FileManager
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
func (e *Encryptor) validateKey() {
	if len(e.Key) != 16 && len(e.Key) != 24 && len(e.Key) != 32 {
		log.Fatalln("[-] Invalid AES key length")
	}
}

// readInputFile reads the contents of the input file
func (e *Encryptor) readInputFile(id int) []byte {
	data, err := os.ReadFile(e.FileManager.InputFilePath)
	if err != nil {
		// I want this put into a separate list.
		log.Printf("[-] [Worker %d] Error reading input file: %s\n", id, err)
	}
	return data
}

// createCipherBlock creates a new AES cipher block
func (e *Encryptor) createCipherBlock() cipher.Block {
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		log.Fatalln("[-] Error creating AES cipher block:", err)
	}
	return block
}

// createGCM creates a GCM cipher for AES
func (e *Encryptor) createGCM(block cipher.Block) cipher.AEAD {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalln("[-] Error creating GCM cipher:", err)
	}
	return aesGCM
}

// generateNonce generates a random nonce
func (e *Encryptor) generateNonce(aesGCM cipher.AEAD) []byte {
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalln("[-] Error generating nonce:", err)
	}
	return nonce
}

// encryptData encrypts plaintext using AES-GCM
func (e *Encryptor) encryptData(aesGCM cipher.AEAD, nonce, plaintext []byte) []byte {
	return aesGCM.Seal(nil, nonce, plaintext, nil)
}

// writeToFile writes data to a specified file
func (e *Encryptor) writeToFile(filePath string, data []byte, id int) {
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		log.Printf("[-] [Worker %d] Error writing to file %s: %v", id, filePath, err)
	}
	log.Printf("[+] [Worker %d] Successfully wrote to file: %s\n", id, filePath)
}

// Encrypt encrypts the input file and writes the result to the encrypted file
func (e *Encryptor) Encrypt(id int) {
	e.validateKey()

	// Read plaintext from input file
	plaintext := e.readInputFile(id)

	// Create AES cipher block and GCM
	block := e.createCipherBlock()
	aesGCM := e.createGCM(block)

	// Generate nonce and encrypt plaintext
	nonce := e.generateNonce(aesGCM)
	ciphertext := e.encryptData(aesGCM, nonce, plaintext)

	// Combine nonce and ciphertext
	finalOutput := append(nonce, ciphertext...)

	// Write encrypted data to the encrypted file
	e.writeToFile(e.FileManager.EncryptedFilePath, finalOutput, id)
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
