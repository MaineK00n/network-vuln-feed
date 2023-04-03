package yamaha

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdYAMAHA() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "yamaha",
		Short:   "create a template for a Vuls format advisory from YAMAHA security advisory",
		Example: "$ network-vuln-feed template yamaha",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
