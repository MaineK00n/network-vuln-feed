package validate

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/network-vuln-feed/pkg/validate"
)

func NewCmdValidate() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "validate <file>",
		Short:   "validate that a given advisory meets the Vuls format",
		Example: "$ network-vuln-feed validate FG-IR-23-001.json",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := validate.Validate(args[0]); err != nil {
				return errors.Wrap(err, "failed to validate")
			}
			return nil
		},
	}

	return cmd
}
