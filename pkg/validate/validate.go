package validate

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

func Validate(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "failed to open %s", path)
	}
	defer f.Close()

	var a Advisory
	if err := json.NewDecoder(f).Decode(&a); err != nil {
		return errors.Wrap(err, "failed to decode")
	}

	return nil
}
