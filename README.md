# Reaperware

Threat emulation, post exploitation to test the Blue Team against encrypted systems

<h1 align="center">
<br>
<img src=Screenshots/reaperware.png >
<br>
Reaperware
</h1>

## Liability

Think before you type, I am not responsible for the misuse of this tool.
This project is specifically for threat emulation and helping Red/Blue/Purple Teams with their objectives.
If you found this tool useful, pay it forward and help the next person out.

## Description
This tool will run through Linux and Windows file systems, looking for the standard extensions to encrypt.
Currently two options exist, Encrypt and Decrypt 

## How It Works

* An RSA private and public key are generated and saved to files
* An AES key is generated, hex encoded and saved to a file
* A system wide search is triggered to find files that would typically be useful to humans
* The files are then encrypted using the AES key, the original files deleted
* The Hex Encoded AES key is then encrypted using the RSA public key, encrypted_aes_key.bin
* The encrypted files on the compromised host are then decrypted, how?
* The encrypted_aes_key.bin is decrypted using only the RSA private key
* A file search is used to find our files with the .reaperware extension
* The decrypted AES key is then used to decrypt these files and restore the original extension

The way a threat could screw this up is leaving behind the Private RSA key.
Make sure to move the Private key (private_key.pem), plaintext AES key (aes_key.txt), and the encrypted_aes_key.bin to a secure location.
The real answer is to code up another location to store these files and not log/write to disk.


## How To

Build using Docker:

```
docker build -t reaperware -f Dockerfile .
```

Copy the binary that you need:

* Windows
```
docker cp e8951868b237:/root/cmd/reaperware.exe reaperware.exe
```

* Linux
```
docker cp e8951868b237:/root/cmd/reaperware reaperware
```

Send it

## Next Steps
* Change the desktop background with note
* Add a note.txt file to the Desktop
* Exfil Private RSA, encrypted AES, and all encrypted files