package fortinet

import (
	"fmt"

	"github.com/MaineK00n/network-vuln-feed/pkg/template/fortinet"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdFortinet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fortinet <fortinet CVRF>",
		Short:   "create a template for a Vuls format advisory from fortinet CVRF",
		Example: "$ network-vuln-feed template fortinet FG-IR-23-001_cvrf.xml",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := fortinet.Template(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to generate vuls format security advisory")
			}
			fmt.Println(s)
			return nil
		},
	}

	return cmd
}
