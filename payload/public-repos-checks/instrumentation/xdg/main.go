package main

import (
	"fmt"
	"log"

	"github.com/adrg/xdg"
)

func main() {
	// Display XDG Base Directory paths
	fmt.Printf("Data Home: %s\n", xdg.DataHome)
	fmt.Printf("Config Home: %s\n", xdg.ConfigHome)
	fmt.Printf("Cache Home: %s\n", xdg.CacheHome)
	
	// Create a config file path
	configPath, err := xdg.ConfigFile("myapp/config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Config file path: %s\n", configPath)
	
	// Display user directories
	fmt.Printf("Desktop: %s\n", xdg.UserDirs.Desktop)
	fmt.Printf("Downloads: %s\n", xdg.UserDirs.Download)
}
