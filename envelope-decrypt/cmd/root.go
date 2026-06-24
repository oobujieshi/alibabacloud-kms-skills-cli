package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "envelope-decrypt",
	Short: "KMS envelope decryption tool - decrypt files encrypted with KMS-managed keys",
	Long: `KMS envelope decryption tool using Alibaba Cloud KMS v2 SDK.
Credentials auto-resolved via default credential chain (same as kmscli/aliyun-cli):
  ENV vars → ~/.aliyun/config.json → ECS RAM role → credentials URI`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var (
	decryptInFile            string
	decryptData              string
	decryptOutFile           string
	decryptEncryptionContext string
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
