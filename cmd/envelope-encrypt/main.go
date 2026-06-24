// Envelope encrypt: GenerateDataKey + AES-256-GCM local encryption.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/oobujieshi/alibabacloud-kms-skills-cli/pkg/kms"
	"github.com/spf13/cobra"
)

var (
	keyID            string
	inFile, inData   string
	outFile          string
	encCtxRaw        string
	keySpec          string
	numBytes         int
)

func main() {
	root := &cobra.Command{
		Use:   "envelope-encrypt",
		Short: "KMS envelope encryption (GenerateDataKey + AES-256-GCM)",
	}
	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt data",
		RunE:  runEncrypt,
	}
	encryptCmd.Flags().StringVar(&keyID, "key-id", "", "KMS CMK ID or alias (required)")
	encryptCmd.Flags().StringVar(&inData, "data", "", "Plaintext string to encrypt")
	encryptCmd.Flags().StringVar(&inFile, "in-file", "", "Input file, '-' for stdin")
	encryptCmd.Flags().StringVar(&outFile, "out-file", "", "Output file, stdout if omitted")
	encryptCmd.Flags().StringVar(&encCtxRaw, "encryption-context", "", "JSON key-value pairs")
	encryptCmd.Flags().StringVar(&keySpec, "key-spec", "", "AES_256 or AES_128")
	encryptCmd.Flags().IntVar(&numBytes, "number-of-bytes", 32, "Key length 1-1024")
	encryptCmd.MarkFlagRequired("key-id")
	root.AddCommand(encryptCmd)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if inData == "" && inFile == "" {
		return fmt.Errorf("either --data or --in-file is required")
	}
	if inData != "" && inFile != "" {
		return fmt.Errorf("--data and --in-file are mutually exclusive")
	}
	var encCtx map[string]interface{}
	if encCtxRaw != "" {
		if err := json.Unmarshal([]byte(encCtxRaw), &encCtx); err != nil {
			return fmt.Errorf("parse --encryption-context: %w", err)
		}
	}
	client, err := kms.CreateClient()
	if err != nil {
		return fmt.Errorf("create KMS client: %w", err)
	}
	plainKey, encryptedKey, err := kms.GenerateDataKey(client, keyID, keySpec, int32(numBytes), encCtx)
	if err != nil {
		return err
	}
	input, err := readInput(inFile, inData)
	if err != nil {
		return err
	}
	key, _ := base64.StdEncoding.DecodeString(plainKey)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ct := aesgcm.Seal(nil, nonce, input, nil)
	out := encryptedKey + "\n" + base64.StdEncoding.EncodeToString(nonce) + "\n" + base64.StdEncoding.EncodeToString(ct)
	return writeOutput(outFile, out)
}

func readInput(path, data string) ([]byte, error) {
	if data != "" {
		return []byte(data), nil
	}
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path, data string) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.WriteString(data)
		return err
	}
	return os.WriteFile(path, []byte(data), 0644)
}
