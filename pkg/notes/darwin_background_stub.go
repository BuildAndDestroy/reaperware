//go:build !darwin

package notes

// changeDarwinBackground is only used when runtime.GOOS == "darwin"; stubbed on other targets for linking.
func changeDarwinBackground(string) error {
	return nil
}
