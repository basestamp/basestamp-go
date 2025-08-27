package main

import (
	"fmt"
	"log"

	"github.com/basestamp/basestamp-go"
)

func main() {
	// Initialize the client
	client := basestamp.NewClient()

	// Calculate hash of your data
	hash := basestamp.CalculateSHA256("Hello, BaseStamp!")
	fmt.Printf("Hash: %s\n", hash)

	// Submit hash for timestamping
	fmt.Println("Submitting hash for timestamping...")
	stampID, err := client.SubmitSHA256(hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Stamp ID: %s\n", stampID)

	// Get the stamp with proof (wait for blockchain confirmation)
	fmt.Println("Waiting for blockchain confirmation...")
	stamp, err := client.GetStamp(stampID, nil) // Use defaults (Wait: true)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the stamp
	valid, err := stamp.Verify(hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Stamp is valid: %v\n", valid)

	// Get additional information
	stampedAt, err := stamp.GetStampedAt()
	if err != nil {
		log.Printf("Could not get stamped time: %v\n", err)
	} else {
		fmt.Printf("Stamped at: %v\n", stampedAt)
	}

	// Get blockchain information
	blockchainInfo, err := stamp.GetBlockchainInfo()
	if err != nil {
		log.Printf("Could not get blockchain info: %v\n", err)
	} else {
		fmt.Printf("Blockchain info: %+v\n", blockchainInfo)
	}

	fmt.Println("✅ Successfully timestamped and verified!")

	// Example of file-based operations
	fmt.Println("\n--- File-based operations ---")
	
	// Create a FileStamp from a file (if we had one)
	// fileStamp, err := basestamp.CreateFileStamp("document.pdf")
	// if err != nil {
	//     log.Fatal(err)
	// }
	//
	// // Save the FileStamp to disk
	// err = basestamp.SaveFileStamp(fileStamp, "document.pdf.basestamp")
	// if err != nil {
	//     log.Fatal(err)
	// }
	//
	// // Load and verify later
	// loadedStamp, err := basestamp.LoadFileStamp("document.pdf.basestamp")
	// if err != nil {
	//     log.Fatal(err)
	// }
	//
	// valid, err := basestamp.VerifyFileStamp("document.pdf", "document.pdf.basestamp")
	// if err != nil {
	//     log.Fatal(err)
	// }
	// fmt.Printf("File stamp is valid: %v\n", valid)

	// Example of direct hash calculation
	data := "Some important document content"
	hash2 := basestamp.CalculateSHA256(data)
	fmt.Printf("Data hash: %s\n", hash2)
}