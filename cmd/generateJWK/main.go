package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nais/jwker/utils"
)

func main() {
	jwk, err := utils.GenerateJWK()
	if err != nil {
		fmt.Printf("Error generating jwk: %s", err)
		os.Exit(1)
	}
	json, err := json.MarshalIndent(jwk, "", " ")
	if err != nil {
		fmt.Printf("Error parsing to json: %s", err)
		os.Exit(1)
	}
	fmt.Println("Copy the following to the path you provide in 'azureJWKFile':")
	fmt.Printf(string(json))
}
