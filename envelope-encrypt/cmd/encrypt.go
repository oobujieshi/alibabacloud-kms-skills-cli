package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/envelope-encrypt/kms"
	"github.com/spf13/cobra"
)

func init() {
	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a file or string using KMS envelope encryption",
		Long: `Encrypt data using KMS envelope encryption (GenerateDataKey + AES-256-GCM).
Output format: 3 lines, each base64-encoded (encrypted_key / nonce / ciphertext).

Use --data for string input, or --in-file for file/stdin input (mutually exclusive).
Omit --out-file to print result to stdout.`,
		RunE: runEncrypt,
	}
	encryptCmd.Flags().StringVar(&encryptKeyId, "key-id", "", "KMS CMK ID or alias (required)")
	encryptCmd.Flags().StringVar(&encryptInFile, "in-file", "", "Input file path, '-' for stdin (use --data instead for string input)")
	encryptCmd.Flags().StringVar(&encryptData, "data", "", "Plaintext string to encrypt (mutually exclusive with --in-file)")
	encryptCmd.Flags().StringVar(&encryptOutFile, "out-file", "", "Output file path, defaults to stdout if omitted")
	encryptCmd.Flags().StringVar(&encryptEncryptionContext, "encryption-context", "", "JSON key-value pairs for KMS EncryptionContext, e.g. '{\"key\":\"value\"}'")
	encryptCmd.Flags().StringVar(&encryptKeySpec, "key-spec", "", "Data key spec: AES_256 or AES_128 (default AES_256)")
	encryptCmd.Flags().IntVar(&encryptNumberOfBytes, "number-of-bytes", 32, "Data key length in bytes, 1-1024 (default 32)")
	encryptCmd.MarkFlagRequired("key-id")

	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	// Parse encryption context
	encCtx, err := parseEncryptionContext(encryptEncryptionContext)
	if err != nil {
		return fmt.Errorf("parse --encryption-context: %w", err)
	}

	// Create KMS client (default credential chain)
	kmsClient, err := kms.CreateKmsClient()
	if err != nil {
		return fmt.Errorf("create KMS client: %w", err)
	}

	// Step 1: Generate data key via KMS
	plainKey, encryptedKey, err := kms.GenerateDataKey(kmsClient, encryptKeyId, encryptKeySpec, int32(encryptNumberOfBytes), encCtx)
	if err != nil {
		return fmt.Errorf("GenerateDataKey: %w", err)
	}

	// Step 2: Read input (--data or --in-file)
	var inData []byte
	if encryptData != "" {
		if encryptInFile != "" {
			return fmt.Errorf("--data and --in-file are mutually exclusive")
		}
		inData = []byte(encryptData)
	} else {
		if encryptInFile == "" {
			return fmt.Errorf("either --data or --in-file is required")
		}
		inData, err = readInput(encryptInFile)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	}

	// Step 3: Local AES-256-GCM encrypt
	key, err := base64.StdEncoding.DecodeString(plainKey)
	if err != nil {
		return fmt.Errorf("decode plain key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	cipherText := aesgcm.Seal(nil, nonce, inData, nil)

	// Step 4: Format and write output (3-line base64)
	out := encryptedKey + "\n" +
		base64.StdEncoding.EncodeToString(nonce) + "\n" +
		base64.StdEncoding.EncodeToString(cipherText)

	if err := writeOutput(encryptOutFile, []byte(out)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "envelope encrypt ok\n")
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
