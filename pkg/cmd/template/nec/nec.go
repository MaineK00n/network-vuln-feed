package nec

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdNEC() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "nec",
		Short:   "create a template for a Vuls format advisory from NEC security advisory",
		Example: "$ network-vuln-feed template nec",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
