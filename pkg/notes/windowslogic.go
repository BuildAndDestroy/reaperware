package notes

import (
	"fmt"
	"os/exec"
)

// changeWindowsBackground updates the wallpaper through PowerShell.
// This avoids fragile manual syscall handling and fails with a normal error.
func changeWindowsBackground(imagePath string) error {
	script := fmt.Sprintf(
		`Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class W{ [DllImport("user32.dll", SetLastError=true)] public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);}'; [W]::SystemParametersInfo(20,0,"%s",3)`,
		imagePath,
	)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set wallpaper: %w: %s", err, string(output))
	}

	return nil
}
