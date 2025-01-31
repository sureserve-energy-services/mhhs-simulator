package services

import "ssesuk/mhhs/simulator/domain"

type requestService struct {
	request *domain.Request
}

func NewService(request *domain.Request) *requestService {
	return &requestService{request: request}
}

func (service *requestService) ExecuteRequest() {

}
