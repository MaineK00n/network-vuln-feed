package cisco

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdCisco() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cisco <cisco CVRF>",
		Short:   "create a template for a Vuls format advisory from cisco CVRF",
		Example: "$ network-vuln-feed template cisco cisco-sa-stealth-rce-2hYb9KFK_cvrf.xml",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
