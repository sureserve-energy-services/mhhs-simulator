package main

import (
	"flag"
	"ssesuk/mhhs/simulator/domain"
	"ssesuk/mhhs/simulator/services"
	"strings"
)

func main() {
	var authOnly bool
	flag.BoolVar(&authOnly, "authonly", false, "Only carry out authentication")

	var url string
	flag.StringVar(&url, "url", "", "URL to root of the endpoint.")

	var scenarios string
	flag.StringVar(&scenarios, "scenarios", "", "List of comma seperated testing scenarios. Example BP008,BP009")
	flag.Parse()

	scenarioList := strings.Split(scenarios, ",")

	for _, scenario := range scenarioList {
		request := domain.Request{BaseUrl: url, AuthOnly: authOnly, RequestType: getRequestTypeFromScenario(scenario)}
		requestService := services.NewService(&request)
		requestService.ExecuteRequest()
	}
}

func getRequestTypeFromScenario(scenario string) domain.RequestType {
	switch strings.ToLower(scenario) {
	case "bp008":
		return domain.BP008
	default:
		return domain.BP008
	}
}
