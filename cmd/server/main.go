package main

import (
	"log"
	"os"

	"github.com/kurk4m/go_util_ssh/ssh"
)

func main() {
	var (
		err error
	)

	authorizedKeysBytes, err := os.ReadFile("mykey.pub")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys %v", err)
	}

	privateKey, err := os.ReadFile("server.pem")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys %v", err)
	}

	if err = ssh.StartServer(privateKey, authorizedKeysBytes); err != nil {
		log.Fatalf("Failed to load authorized_keys %v", err)
	}

}
