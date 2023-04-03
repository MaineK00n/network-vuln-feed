package paloalto

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdPaloAlto() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "paloalto (<paloalto JSON URL>)",
		Short: "discover new and updated advisories for paloalto",
		Example: `$ network-vuln-feed discover paloalto
$ network-vuln-feed discover paloalto https://security.paloaltonetworks.com/json/PAN-SA-2023-0001`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
