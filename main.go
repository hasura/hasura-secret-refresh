package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hasura/hasura-secret-refresh/server"
)

func main() {
	configPath := flag.String(server.ConfigFileCliFlag, server.ConfigFileDefaultPath, server.ConfigFileCliFlagDescription)
	flag.Parse()
	if server.IsDefaultPath(configPath) {
		log.Printf("Looking for config in default path %s", *configPath)
	}
	log.Printf("Looking for config in path %s", *configPath)
	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to read config file: %s", err))
	}
	log.Printf("Config file found")
	config, err := server.ParseConfig(data)
	if err != nil {
		log.Fatalf("Unable to parse config file: %s", err)
	}
	server.Serve(config)
}
