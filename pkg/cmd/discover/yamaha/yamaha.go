package yamaha

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdYAMAHA() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "yamaha",
		Short:   "discover new and updated advisories for yamaha",
		Example: "$ network-vuln-feed discover yamaha",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
