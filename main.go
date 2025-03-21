package main

import (
	"flag"
	"fmt"
	"ssesuk/mhhs/simulator/domain"
	"ssesuk/mhhs/simulator/services"
	"strings"
)

func main() {
	fmt.Printf("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	fmt.Println(getIntroText())
	fmt.Printf("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

	var authOnly bool
	flag.BoolVar(&authOnly, "authonly", false, "Only carry out authentication")

	var url string
	flag.StringVar(&url, "url", "", "URL to root of the endpoint.")

	var privateKeyPath string
	flag.StringVar(&privateKeyPath, "privateKeyPath", "", "Path to the private key file for signature signing.")

	var certPath string
	flag.StringVar(&certPath, "certPath", "", "Path to the digital certificate file.")

	var interfaces string
	flag.StringVar(&interfaces, "interfaces", "", "List of comma seperated interfaces. Example IF033,IF034 etc")
	flag.Parse()

	scenarioList := strings.Split(interfaces, ",")

	fmt.Println("Testing interfaces...")

	for _, scenario := range scenarioList {
		fmt.Println("-----------------------------------------------------------")
		fmt.Println(scenario)

		request := domain.Request{
			BaseUrl:        url,
			AuthOnly:       authOnly,
			InterfaceType:  getRequestTypeFromScenario(scenario),
			PrivateKeyPath: privateKeyPath,
			CertPath:       certPath}

		requestService := services.NewService(&request)
		response := requestService.ExecuteRequest()

		fmt.Println("Response:" + response)
		fmt.Println("-----------------------------------------------------------")
	}
}

func getRequestTypeFromScenario(scenario string) domain.InterfaceType {
	switch strings.ToLower(scenario) {
	case "if033":
		return domain.IF033
	case "if034":
		return domain.IF033
	case "if035":
		return domain.IF033
	default:
		return domain.IF033
	}
}

func getIntroText() string {
	return `.d8888b.                                                                            888b     d888 888    888 888    888  .d8888b.        .d8888b.  d8b               
d88P  Y88b                                                                           8888b   d8888 888    888 888    888 d88P  Y88b      d88P  Y88b Y8P               
Y88b.                                                                                88888b.d88888 888    888 888    888 Y88b.           Y88b.                        
 "Y888b.   888  888 888d888 .d88b.  .d8888b   .d88b.  888d888 888  888  .d88b.       888Y88888P888 8888888888 8888888888  "Y888b.         "Y888b.   888 88888b.d88b.  
    "Y88b. 888  888 888P"  d8P  Y8b 88K      d8P  Y8b 888P"   888  888 d8P  Y8b      888 Y888P 888 888    888 888    888     "Y88b.          "Y88b. 888 888 "888 "88b 
      "888 888  888 888    88888888 "Y8888b. 88888888 888     Y88  88P 88888888      888  Y8P  888 888    888 888    888       "888            "888 888 888  888  888 
Y88b  d88P Y88b 888 888    Y8b.          X88 Y8b.     888      Y8bd8P  Y8b.          888   "   888 888    888 888    888 Y88b  d88P      Y88b  d88P 888 888  888  888 
 "Y8888P"   "Y88888 888     "Y8888   88888P'  "Y8888  888       Y88P    "Y8888       888       888 888    888 888    888  "Y8888P"        "Y8888P"  888 888  888  888`
}
