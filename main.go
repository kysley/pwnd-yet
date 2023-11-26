package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const numba = 123123123123123

func main() {
	var rootCmd = &cobra.Command{
		Use:     "pwnedyet",
		Aliases: []string{"pwn"},
		Short:   "pwnedyet is a CLI for checking something",
		Run: func(cmd *cobra.Command, args []string) {
			run, _ := cmd.Flags().GetString("o")
			if len(run) > 0 {
				sha := sha1Hash(run)
				prefix := sha[:5]
				suffix := sha[5:]

				if isPasswordPwned(prefix, suffix) {
					fmt.Println("Password pwned 😵")
				} else {
					fmt.Println("No results found.")
				}
			} else {
				checkPasswords()
			}
		},
	}

	var pwCmd = &cobra.Command{
		Use:   "pw",
		Short: "Password related commands",
	}

	var addCmd = &cobra.Command{
		Use:   "add [name] [password]",
		Short: "Add a new item",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			addPassword(args[0], args[1])
		},
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all items",
		Run: func(cmd *cobra.Command, args []string) {
			listPasswords()
		},
	}

	pwCmd.AddCommand(addCmd, listCmd)
	rootCmd.AddCommand(pwCmd)
	rootCmd.PersistentFlags().String("o", "", "Run once without saving")
	pwn()
	rootCmd.Execute()
}

func addPassword(name, password string) {
	sha := sha1Hash(password)
	shaEnc, _ := Encrypt(sha, MySecret)
	entry := fmt.Sprintf("%s:%s\n", name, shaEnc)

	file, err := os.OpenFile("pwn.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	defer file.Close()

	if _, err := file.WriteString(entry); err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Println("Password added successfully")
}

func listPasswords() {
	data, err := ioutil.ReadFile("pwn.txt")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(data))
}

func sha1Hash(input string) string {
	hasher := sha1.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func checkPasswords() {
	file, err := os.Open("pwn.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			fmt.Println("Invalid line format:", line)
			continue
		}

		name := parts[0]
		fullSHA1, _ := Decrypt(parts[1], MySecret)
		if len(fullSHA1) < 5 {
			fmt.Println("Invalid SHA1 hash for", name)
			continue
		}

		prefix := fullSHA1[:5]
		suffix := fullSHA1[5:]
		fmt.Println("Checking", name)
		if isPasswordPwned(prefix, suffix) {
			fmt.Println("Password pwned 😵")
		} else {
			fmt.Println("No results found.")
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}

func isPasswordPwned(prefix, suffix string) bool {
	url := "https://api.pwnedpasswords.com/range/" + prefix
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making request:", err)
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return false
	}

	hashes := strings.Split(string(body), "\r\n")
	for _, hash := range hashes {
		parts := strings.Split(hash, ":")
		if len(parts) < 2 {
			continue
		}

		if strings.ToUpper(suffix) == parts[0] {
			return true
		}
	}
	return false
}

// Reads the key from key.txt and returns it
func readKey() ([]byte, error) {
	key, err := ioutil.ReadFile("key.txt")
	if err != nil {
		return nil, err
	}
	return key, nil
}

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

// This should be in an env file in production
const MySecret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func pwn() {
	text, err := ioutil.ReadFile("ascii.txt")
	if err != nil {
		panic(err)
	}
	println(string(text))
}
