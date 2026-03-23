package notes

import (
	"fmt"
	"unicode/utf16"
	"unsafe"
)

// UTF16PtrFromString converts a Go string to a pointer to a null-terminated UTF-16 encoded string.
func UTF16PtrFromString(s string) *uint16 {
	u := utf16.Encode([]rune(s + "\x00"))
	return &u[0]
}

// LoadLibrary manually loads a DLL and returns its handle.
func LoadLibrary(dllName string) uintptr {
	libNamePtr := UTF16PtrFromString(dllName)
	ret, _, _ := callKernel32("LoadLibraryW", uintptr(unsafe.Pointer(libNamePtr)))
	if ret == 0 {
		panic(fmt.Sprintf("failed to load library: %s", dllName))
	}
	return ret
}

// GetProcAddress retrieves the address of a procedure in a loaded DLL.
func GetProcAddress(dll uintptr, procName string) uintptr {
	namePtr := uintptr(unsafe.Pointer(&[]byte(procName + "\x00")[0]))
	ret, _, _ := callKernel32("GetProcAddress", dll, namePtr)
	if ret == 0 {
		panic(fmt.Sprintf("failed to find procedure: %s", procName))
	}
	return ret
}

// callKernel32 dynamically calls functions in kernel32.dll.
func callKernel32(procName string, args ...uintptr) (uintptr, uintptr, error) {
	kernel32 := LoadLibrary("kernel32.dll")
	defer FreeLibrary(kernel32)

	procAddr := GetProcAddress(kernel32, procName)

	// Call the function with arguments
	switch len(args) {
	case 0:
		return syscall3(procAddr, 0, 0, 0)
	case 1:
		return syscall3(procAddr, args[0], 0, 0)
	case 2:
		return syscall3(procAddr, args[0], args[1], 0)
	case 3:
		return syscall3(procAddr, args[0], args[1], args[2])
	default:
		panic("too many arguments")
	}
}

// syscall3 performs a raw system call with up to 3 arguments.
func syscall3(addr, arg1, arg2, arg3 uintptr) (r1, r2 uintptr, lastErr error) {
	// Invoke a system call, placeholder for actual implementation
	// Go does not support inline assembly directly, so this part is a placeholder.
	return uintptr(0), uintptr(0), nil
}

// FreeLibrary frees a loaded DLL.
func FreeLibrary(dll uintptr) {
	_, _, _ = callKernel32("FreeLibrary", dll)
}

// changeWindowsBackground changes the desktop wallpaper using SystemParametersInfoW.
func changeWindowsBackground(imagePath string) error {
	// Load user32.dll
	user32 := LoadLibrary("user32.dll")
	defer FreeLibrary(user32)

	// Get the address of SystemParametersInfoW
	// systemParametersInfo := GetProcAddress(user32, "SystemParametersInfoW")
	GetProcAddress(user32, "SystemParametersInfoW")

	// Convert the image path to UTF-16
	imagePathPtr := UTF16PtrFromString(imagePath)

	// Call SystemParametersInfoW
	ret, _, _ := callKernel32("SystemParametersInfoW", SPI_SETDESKWALLPAPER, 0, uintptr(unsafe.Pointer(imagePathPtr)), SPIF_UPDATEINIFILE|SPIF_SENDCHANGE)

	if ret == 0 {
		return fmt.Errorf("failed to set wallpaper")
	}

	fmt.Println("Wallpaper successfully changed!")
	return nil
}
