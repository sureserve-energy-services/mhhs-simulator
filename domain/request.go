package domain

type Request struct {
	BaseUrl        string
	AuthOnly       bool
	InterfaceType  InterfaceType
	PrivateKeyPath string
	CertPath       string
}
