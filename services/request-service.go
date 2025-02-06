package services

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"ssesuk/mhhs/simulator/domain"
	"strings"
)

type authenticationParameters struct {
	Signature   string
	Date        string
	Certificate string
	MessageHash string
}

type requestService struct {
	request *domain.Request
}

func NewService(request *domain.Request) *requestService {
	return &requestService{request: request}
}

func (service *requestService) ExecuteRequest() {
	url := fmt.Sprintf("%s/requests", service.request.BaseUrl)
	requestVerb, requestDestination := "POST", "/requests"
	messageBody := service.getMessageBody()
	messageBodyString := string(messageBody)
	date := "2021-04-20T15:00:00Z"

	validEncodedCertificate, err := getValidEncodedCertificate()

	if err != nil {
		fmt.Println("Error:", err)
	}

	authenticationParameters, err := getRequestAuthenticationParameters(messageBodyString, requestVerb, requestDestination, date, validEncodedCertificate)

	req, err := http.NewRequest(requestVerb, url, bytes.NewBuffer(messageBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DIP-Signature", authenticationParameters.Signature)
	req.Header.Set("X-DIP-Signature-Date", authenticationParameters.Date)
	req.Header.Set("X-DIP-Certificate", authenticationParameters.Certificate)
	req.Header.Set("X-DIP-Content-Hash", authenticationParameters.MessageHash)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	defer resp.Body.Close()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Println("Response:", string(body))
}

func (service *requestService) getMessageBody() []byte {
	var fileName string

	switch service.request.RequestType {
	case domain.BP008:
		fileName = "requests/change_of_supplier.json"
	}

	fileNameBytes, err := os.ReadFile(fileName)

	if err != nil {
		fmt.Println("Error loading request file:", err)
	}

	return fileNameBytes
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile("authentication/testcerts/dip/valid/dip_rsa_privatekey_pkcs1.pem")

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyFile)

	if block == nil {
		return nil, errors.New("could not decode private key certificate")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	return key, nil
}

func getRequestAuthenticationParameters(messageBody, requestVerb, requestDestination, date, encodedCertificate string) (*authenticationParameters, error) {
	messageHash := sha256.New()
	messageHash.Write([]byte(messageBody))
	messageHashSum := messageHash.Sum(nil)
	encodedMessageHash := base64.StdEncoding.EncodeToString(messageHashSum)

	signatureStringBuilder := strings.Builder{}
	signatureStringBuilder.WriteString(requestVerb)
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(requestDestination)
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(date)
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(encodedMessageHash)

	signatureString := signatureStringBuilder.String()
	hashedSignature := sha256.New()
	hashedSignature.Write([]byte(signatureString))
	hashedSignatureSum := hashedSignature.Sum(nil)

	privateKey, err := getPrivateKey()

	if err != nil {
		return nil, err
	}

	signedSignature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, []byte(hashedSignatureSum))

	if err != nil {
		return nil, err
	}

	encodedSignedSignature := base64.StdEncoding.EncodeToString(signedSignature)

	authenticationParameters := authenticationParameters{
		Signature:   encodedSignedSignature,
		Date:        date,
		Certificate: encodedCertificate,
		MessageHash: encodedMessageHash,
	}

	return &authenticationParameters, nil
}

func getValidEncodedCertificate() (string, error) {
	publicKey, err := os.ReadFile("authentication/testcerts/dip/valid/dip_cert.crt")

	if err != nil {
		return "", err
	}

	encodedCertificate := base64.StdEncoding.EncodeToString(publicKey)
	return encodedCertificate, nil
}

func getInvalidEncodedCertificate() (string, error) {
	publicKey, err := os.ReadFile("authentication/testcerts/dip/invalid/dip_invalid_cert.crt")

	if err != nil {
		return "", err
	}

	encodedCertificate := base64.StdEncoding.EncodeToString(publicKey)
	return encodedCertificate, nil
}
