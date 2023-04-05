package fortinet

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdFortinet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fortinet <fortinet CVRF>",
		Short:   "create a template for a Vuls format advisory from fortinet CVRF",
		Example: "$ network-vuln-feed template fortinet FG-IR-23-001_cvrf.xml",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
