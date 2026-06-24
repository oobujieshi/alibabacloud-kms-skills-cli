package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "envelope-encrypt",
	Short: "KMS envelope encryption tool - encrypt files with KMS-managed keys",
	Long: `KMS envelope encryption tool using Alibaba Cloud KMS v2 SDK.
Credentials auto-resolved via default credential chain (same as kmscli/aliyun-cli):
  ENV vars → ~/.aliyun/config.json → ECS RAM role → credentials URI`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var (
	encryptKeyId             string
	encryptInFile            string
	encryptData              string
	encryptOutFile           string
	encryptEncryptionContext string
	encryptKeySpec           string
	encryptNumberOfBytes     int
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
