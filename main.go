package main

import (
	"flag"
	"ssesuk/mhhs/simulator/domain"
	"ssesuk/mhhs/simulator/services"
)

func main() {
	var authOnly bool
	flag.BoolVar(&authOnly, "authonly", false, "Only carry out authentication")
	flag.Parse()

	request := domain.Request{BaseUrl: "", AuthOnly: authOnly}
	requestService := services.NewService(&request)
	requestService.ExecuteRequest()
}
