//go:build darwin

package notes

import (
	"fmt"
	"os/exec"
)

// changeDarwinBackground sets the desktop picture on macOS via osascript (user session APIs).
func changeDarwinBackground(imagePath string) error {
	script := fmt.Sprintf(
		`tell application "System Events" to tell every desktop to set picture to %q`,
		imagePath,
	)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osascript: %w: %s", err, string(out))
	}
	return nil
}
