package notes

import (
	"log"
	"os/exec"
	"runtime"
	"syscall"
)

func changeLinuxBackground(imagePath string) {
	// Detect the desktop environment
	desktop := detectDesktopEnvironment()

	switch desktop {
	case "gnome":
		// GNOME: Use gsettings to set the wallpaper
		cmd := exec.Command("gsettings", "set", "org.gnome.desktop.background", "picture-uri", "file://"+imagePath)
		err := cmd.Run()
		if err != nil {
			log.Println("[-] Failed to set wallpaper on GNOME:", err)
		} else {
			log.Println("[+] Wallpaper changed successfully on GNOME.")
		}
	case "xfce":
		// XFCE: Use xfconf-query to set the wallpaper
		cmd := exec.Command("xfconf-query", "-c", "xfce4-desktop", "-p", "/backdrop/screen0/monitor0/image-path", "-s", imagePath)
		err := cmd.Run()
		if err != nil {
			log.Println("[-] Failed to set wallpaper on XFCE:", err)
		} else {
			log.Println("[+] Wallpaper changed successfully on XFCE.")
		}
	default:
		// Fallback to `feh` for other environments
		cmd := exec.Command("feh", "--bg-scale", imagePath)
		err := cmd.Run()
		if err != nil {
			log.Println("[-] Failed to set wallpaper with feh:", err)
		} else {
			log.Println("[+] Wallpaper changed successfully using feh.")
		}
	}
}

func detectDesktopEnvironment() string {
	// Check for the desktop environment
	if runtime.GOOS != "linux" {
		return ""
	}
	env := map[string]string{
		"XDG_CURRENT_DESKTOP": "",
		"DESKTOP_SESSION":     "",
	}
	for k := range env {
		env[k] = getenv(k)
	}

	if env["XDG_CURRENT_DESKTOP"] == "GNOME" {
		return "gnome"
	} else if env["DESKTOP_SESSION"] == "xfce" {
		return "xfce"
	}
	return "other"
}

func getenv(key string) string {
	if value, ok := syscall.Getenv(key); ok {
		return value
	}
	return ""
}
