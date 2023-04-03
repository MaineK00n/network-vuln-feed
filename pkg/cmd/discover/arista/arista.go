package arista

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdArista() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "arista (<arista security advisory URL>)",
		Short: "discover new and updated advisories for arista",
		Example: `$ network-vuln-feed discover arista
$ network-vuln-feed discover arista https://www.arista.com/en/support/advisories-notices/security-advisory/17022-security-advisory-0083`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
