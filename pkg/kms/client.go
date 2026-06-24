// Package kms provides shared Alibaba Cloud KMS client creation.
// Used by all cmd/ subcommands in this repo.
package kms

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
)

const (
	metadataURL       = "http://100.100.100.200/latest/meta-data/region-id"
	kmsVpcEndpoint    = "kms-vpc.%s.aliyuncs.com"
	kmsPublicEndpoint = "kms.%s.aliyuncs.com"
	httpTimeout       = 5 * time.Second
)

// CreateClient creates a KMS v2 SDK client using the default credential chain.
func CreateClient() (*kms20160120.Client, error) {
	cred, err := credentials.NewCredential(nil)
	if err != nil {
		return nil, err
	}
	region, err := getRegion()
	if err != nil {
		return nil, fmt.Errorf("get region: %w", err)
	}
	endpoint := getEndpoint(region)
	cfg := &openapi.Config{
		Credential: cred,
		Endpoint:   tea.String(endpoint),
	}
	return kms20160120.NewClient(cfg)
}

func getEndpoint(region string) string {
	if os.Getenv("ENDPOINT_TYPE") == "Public" {
		return fmt.Sprintf(kmsPublicEndpoint, region)
	}
	return fmt.Sprintf(kmsVpcEndpoint, region)
}

func getRegion() (string, error) {
	if v := os.Getenv("REGION_ID"); v != "" {
		return v, nil
	}
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(metadataURL)
	if err != nil {
		return "", fmt.Errorf("region: set REGION_ID or run on ECS")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("region: ECS metadata returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GenerateDataKey wraps KMS GenerateDataKey API.
func GenerateDataKey(client *kms20160120.Client, keyID, keySpec string, numBytes int32, encCtx map[string]interface{}) (plaintext, ciphertext string, err error) {
	req := &kms20160120.GenerateDataKeyRequest{
		KeyId:             tea.String(keyID),
		NumberOfBytes:     &numBytes,
		EncryptionContext: encCtx,
	}
	if keySpec != "" {
		req.KeySpec = tea.String(keySpec)
	}
	resp, err := client.GenerateDataKey(req)
	if err != nil {
		return "", "", fmt.Errorf("GenerateDataKey: %w", err)
	}
	if resp.Body == nil || resp.Body.Plaintext == nil || resp.Body.CiphertextBlob == nil {
		return "", "", fmt.Errorf("GenerateDataKey: incomplete response")
	}
	return tea.StringValue(resp.Body.Plaintext), tea.StringValue(resp.Body.CiphertextBlob), nil
}

// Decrypt wraps KMS Decrypt API.
func Decrypt(client *kms20160120.Client, ciphertextBlob string, encCtx map[string]interface{}) (string, error) {
	req := &kms20160120.DecryptRequest{
		CiphertextBlob:   tea.String(ciphertextBlob),
		EncryptionContext: encCtx,
	}
	resp, err := client.Decrypt(req)
	if err != nil {
		return "", fmt.Errorf("Decrypt: %w", err)
	}
	if resp.Body == nil || resp.Body.Plaintext == nil {
		return "", fmt.Errorf("Decrypt: incomplete response")
	}
	return tea.StringValue(resp.Body.Plaintext), nil
}

// Encrypt wraps KMS Encrypt API (for symmetric key mode).
func Encrypt(client *kms20160120.Client, keyID string, plaintext []byte, encCtx map[string]interface{}) (*kms20160120.EncryptResponseBody, error) {
	req := &kms20160120.EncryptRequest{
		KeyId:             tea.String(keyID),
		Plaintext:         tea.String(string(plaintext)),
		EncryptionContext: encCtx,
	}
	resp, err := client.Encrypt(req)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: %w", err)
	}
	return resp.Body, nil
}
