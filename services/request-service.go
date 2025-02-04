package services

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

}

func getPrivateKey() (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile("testcerts/dip/dip_rsa_privatekey_pkcs1.pem")

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
	publicKey, err := os.ReadFile("certs/dip_cert.crt")

	if err != nil {
		return "", err
	}

	encodedCertificate := base64.StdEncoding.EncodeToString(publicKey)
	return encodedCertificate, nil
}

func getInvalidEncodedCertificate() (string, error) {
	publicKey, err := os.ReadFile("certs/dip_invalid_cert.crt")

	if err != nil {
		return "", err
	}

	encodedCertificate := base64.StdEncoding.EncodeToString(publicKey)
	return encodedCertificate, nil
}
