package fortinet

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdFortinet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fortinet (<fortinet CVRF URL>)",
		Short: "discover new and updated advisories for fortinet",
		Example: `$ network-vuln-feed discover fortinet
$ network-vuln-feed discover fortinet https://www.fortiguard.com/psirt/cvrf/FG-IR-22-488`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
