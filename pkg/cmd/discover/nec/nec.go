package nec

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdNEC() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "nec",
		Short:   "discover new and updated advisories for nec",
		Example: "$ network-vuln-feed discover nec",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
