package services

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
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
	"time"

	"golang.org/x/crypto/pkcs12"
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

func (service *requestService) ExecuteRequest() string {
	url := service.request.BaseUrl
	requestVerb := "POST"
	messageBody := service.getMessageBody()
	messageBodyString := string(messageBody)

	currentTime := time.Now()
	date := currentTime.UTC().Format("2006-01-02T15:04:05.000Z")
	//date := "2025-06-27T14:29:09.061Z"

	validEncodedCertificate, err := service.getEncodedCertificate()

	if err != nil {
		return "Error:" + err.Error()
	}

	authenticationParameters, err := service.getRequestAuthenticationParameters(messageBodyString, requestVerb, url, date, validEncodedCertificate)

	req, err := http.NewRequest(requestVerb, url, bytes.NewBuffer(messageBody))
	req.ContentLength = int64(len(messageBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DIP-Signature", authenticationParameters.Signature)
	req.Header.Set("X-DIP-Signature-Date", authenticationParameters.Date)
	req.Header.Set("X-DIP-Signature-Certificate", authenticationParameters.Certificate)
	req.Header.Set("X-DIP-Content-Hash", authenticationParameters.MessageHash)
	req.Header.Set("User-Agent", "PostmanRuntime/7.44.1")

	pfxData, err := os.ReadFile("Certificate_Sureserve.pfx")
	if err != nil {
		return "Failed to read PFX file: " + err.Error()
	}

	privateKey, cert, err := pkcs12.Decode(pfxData, "495badac-daf0-4bed-ab4b-8e164b4a566f")
	if err != nil {
		return "Failed to decode PFX: " + err.Error()
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
			Certificates:  []tls.Certificate{tlsCert},
		},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)

	if err != nil {
		return "Error:" + err.Error()
	}

	defer resp.Body.Close()

	if resp.Status != "200 OK" {
		errorBody, _ := io.ReadAll(resp.Body)
		return resp.Status + " " + string(errorBody)
	}

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Error reading response:" + err.Error()
	}

	return resp.Status + " - " + string(body)
}

func (service *requestService) getMessageBody() []byte {
	var fileName string

	switch service.request.InterfaceType {
	case domain.IF033:
		fileName = "requests/if-033.json"
	}

	fileNameBytes, err := os.ReadFile(fileName)

	if err != nil {
		fmt.Println("Error loading request file:", err)
	}

	return fileNameBytes
}

func (service *requestService) getPrivateKey() (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile(service.request.PrivateKeyPath)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyFile)

	if block == nil {
		return nil, errors.New("could not decode private key certificate")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}

func (service *requestService) getRequestAuthenticationParameters(messageBody, requestVerb, requestDestination, date, encodedCertificate string) (*authenticationParameters, error) {
	messageHash := sha256.New()
	messageHash.Write([]byte(messageBody))
	messageHashSum := messageHash.Sum(nil)
	encodedMessageHash := base64.StdEncoding.EncodeToString(messageHashSum)

	signatureStringBuilder := strings.Builder{}
	signatureStringBuilder.WriteString(requestVerb)
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(strings.ToLower(requestDestination))
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(date)
	signatureStringBuilder.WriteString(";")
	signatureStringBuilder.WriteString(encodedMessageHash)

	signatureString := signatureStringBuilder.String()
	hashedSignature := sha256.New()
	hashedSignature.Write([]byte(signatureString))
	hashedSignatureSum := hashedSignature.Sum(nil)

	privateKey, err := service.getPrivateKey()

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

func (service *requestService) getEncodedCertificate() (string, error) {
	publicKey, err := os.ReadFile(service.request.CertPath)

	if err != nil {
		return "", err
	}

	keyString := string(publicKey)
	keyString = strings.ReplaceAll(keyString, "\r\n", "\n")
	encodedCertificate := base64.StdEncoding.EncodeToString([]byte(keyString))

	return encodedCertificate, nil
}
