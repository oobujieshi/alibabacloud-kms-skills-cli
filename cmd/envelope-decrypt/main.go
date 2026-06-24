// Envelope decrypt: KMS Decrypt + AES-256-GCM local decryption.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oobujieshi/alibabacloud-kms-skills-cli/pkg/kms"
	"github.com/spf13/cobra"
)

var (
	inFile, inData   string
	outFile          string
	encCtxRaw        string
)

func main() {
	root := &cobra.Command{
		Use:   "envelope-decrypt",
		Short: "KMS envelope decryption (Decrypt + AES-256-GCM)",
	}
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt data",
		RunE:  runDecrypt,
	}
	decryptCmd.Flags().StringVar(&inData, "data", "", "3-line base64 ciphertext string")
	decryptCmd.Flags().StringVar(&inFile, "in-file", "", "Input file, '-' for stdin")
	decryptCmd.Flags().StringVar(&outFile, "out-file", "", "Output file, stdout if omitted")
	decryptCmd.Flags().StringVar(&encCtxRaw, "encryption-context", "", "Must match encryption value")
	root.AddCommand(decryptCmd)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDecrypt(cmd *cobra.Command, args []string) error {
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
	input, err := readInput(inFile, inData)
	if err != nil {
		return err
	}
	lines := strings.SplitN(string(input), "\n", 3)
	if len(lines) != 3 {
		return fmt.Errorf("invalid envelope format: expected 3 lines, got %d", len(lines))
	}
	encKey := strings.TrimSpace(lines[0])
	nonceB64 := strings.TrimSpace(lines[1])
	ctB64 := strings.TrimSpace(lines[2])

	client, err := kms.CreateClient()
	if err != nil {
		return fmt.Errorf("create KMS client: %w", err)
	}
	plainKeyB64, err := kms.Decrypt(client, encKey, encCtx)
	if err != nil {
		return err
	}
	dataKey, _ := base64.StdEncoding.DecodeString(plainKeyB64)
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	ct, _ := base64.StdEncoding.DecodeString(ctB64)
	block, _ := aes.NewCipher(dataKey)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return writeOutput(outFile, string(plaintext))
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
