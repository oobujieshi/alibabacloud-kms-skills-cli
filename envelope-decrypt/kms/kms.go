// Package kms provides KMS client creation following alibabacloud-kms-cli pattern.
// Uses credentials-go default credential chain (no AKSK required).
// Region auto-detected from REGION_ID env or ECS metadata.
// Endpoint defaults to VPC (kms-vpc.{region}.aliyuncs.com).
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

	EndpointTypePublic = "Public"
	EndpointTypeVpc    = "Vpc"
)

// CreateKmsClient creates a KMS v2 SDK client using the default credential chain.
func CreateKmsClient() (*kms20160120.Client, error) {
	credential, err := credentials.NewCredential(nil)
	if err != nil {
		return nil, err
	}

	config := &openapi.Config{
		Credential: credential,
	}

	regionId, err := getRegionId()
	if err != nil {
		return nil, fmt.Errorf("get region id err: %w", err)
	}

	endpointType := getEndpointType()
	if endpointType == EndpointTypePublic {
		config.Endpoint = tea.String(fmt.Sprintf(kmsPublicEndpoint, regionId))
	} else {
		config.Endpoint = tea.String(fmt.Sprintf(kmsVpcEndpoint, regionId))
	}

	return kms20160120.NewClient(config)
}

func getEndpointType() string {
	if v := os.Getenv("ENDPOINT_TYPE"); v != "" {
		return v
	}
	return EndpointTypeVpc
}

func getRegionId() (string, error) {
	if v := os.Getenv("REGION_ID"); v != "" {
		return v, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(metadataURL)
	if err != nil {
		return "", fmt.Errorf("get region id from meta server error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get region id from meta server status invalid: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Decrypt calls KMS Decrypt API to decrypt the data key.
func Decrypt(client *kms20160120.Client, ciphertextBlob string, encCtx map[string]interface{}) (string, error) {
	req := &kms20160120.DecryptRequest{
		CiphertextBlob:   tea.String(ciphertextBlob),
		EncryptionContext: encCtx,
	}
	resp, err := client.Decrypt(req)
	if err != nil {
		return "", fmt.Errorf("Decrypt error: %w", err)
	}
	if resp.Body == nil || resp.Body.Plaintext == nil {
		return "", fmt.Errorf("Decrypt response incomplete")
	}
	return tea.StringValue(resp.Body.Plaintext), nil
}
