package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/envelope-decrypt/kms"
	"github.com/spf13/cobra"
)

func init() {
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a file or string using KMS envelope decryption",
		Long: `Decrypt data that was encrypted with envelope-encrypt.
Input must be the 3-line base64 format (encrypted_key / nonce / ciphertext).

Use --data for string input, or --in-file for file/stdin input (mutually exclusive).
Omit --out-file to print result to stdout.

If --encryption-context was used during encryption, the same value must be provided here.`,
		RunE: runDecrypt,
	}
	decryptCmd.Flags().StringVar(&decryptInFile, "in-file", "", "Input ciphertext file path, '-' for stdin (use --data instead for string input)")
	decryptCmd.Flags().StringVar(&decryptData, "data", "", "Ciphertext string to decrypt, 3-line base64 format (mutually exclusive with --in-file)")
	decryptCmd.Flags().StringVar(&decryptOutFile, "out-file", "", "Output plaintext file path, defaults to stdout if omitted")
	decryptCmd.Flags().StringVar(&decryptEncryptionContext, "encryption-context", "", "JSON key-value pairs, must match the value used during encryption")

	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	// Parse encryption context
	encCtx, err := parseEncryptionContext(decryptEncryptionContext)
	if err != nil {
		return fmt.Errorf("parse --encryption-context: %w", err)
	}

	// Step 1: Read input (--data or --in-file)
	var inData []byte
	if decryptData != "" {
		if decryptInFile != "" {
			return fmt.Errorf("--data and --in-file are mutually exclusive")
		}
		inData = []byte(decryptData)
	} else {
		if decryptInFile == "" {
			return fmt.Errorf("either --data or --in-file is required")
		}
		inData, err = readInput(decryptInFile)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	}

	lines := strings.SplitN(string(inData), "\n", 3)
	if len(lines) != 3 {
		return fmt.Errorf("invalid envelope format: expected 3 lines, got %d", len(lines))
	}
	encryptedKey := strings.TrimSpace(lines[0])
	nonceB64 := strings.TrimSpace(lines[1])
	cipherTextB64 := strings.TrimSpace(lines[2])

	// Step 2: Create KMS client (default credential chain, same as kmscli)
	kmsClient, err := kms.CreateKmsClient()
	if err != nil {
		return fmt.Errorf("create KMS client: %w", err)
	}

	// Step 3: Decrypt data key via KMS
	plainKeyB64, err := kms.Decrypt(kmsClient, encryptedKey, encCtx)
	if err != nil {
		return fmt.Errorf("KMS Decrypt: %w", err)
	}

	// Step 4: Local AES-256-GCM decrypt
	dataKey, err := base64.StdEncoding.DecodeString(plainKeyB64)
	if err != nil {
		return fmt.Errorf("decode data key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextB64)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	// Step 5: Write output
	if err := writeOutput(decryptOutFile, plaintext); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "envelope decrypt ok\n")
	return nil
}

func parseEncryptionContext(raw string) (map[string]interface{}, error) {
	if raw == "" {
		return nil, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}
