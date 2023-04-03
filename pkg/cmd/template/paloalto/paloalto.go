package paloalto

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdPaloAlto() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "paloalto <paloalto JSON>",
		Short:   "create a template for a Vuls format advisory from paloalto JSON",
		Example: "$ network-vuln-feed template paloalto PAN-SA-2023-0001.json",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
