package arista

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdArista() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "arista",
		Short:   "create a template for a Vuls format advisory from arista security advisory",
		Example: "$ network-vuln-feed template arista",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
