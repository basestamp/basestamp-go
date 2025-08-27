package cli

import (
	"encoding/json"
	"os"

	"github.com/basestamp/basestamp-go/types"
)

// saveStampToFile saves a FileStamp to a file
func saveStampToFile(stamp types.FileStamp, filename string) error {
	data, err := json.MarshalIndent(stamp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}