package domain

type Request struct {
	BaseUrl     string
	AuthOnly    bool
	RequestType RequestType
}
