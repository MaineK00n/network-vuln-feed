package fortinet

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/network-vuln-feed/pkg/discover/fortinet"
)

func NewCmdFortinet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fortinet <IR RSS URL> <fortinet advisory root path>",
		Short:   "discover new and updated advisories for fortinet",
		Example: `$ network-vuln-feed discover fortinet https://filestore.fortinet.com/fortiguard/rss/ir.xml ./dest/fortinet`,
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fortinet.Discover(args[0], args[1]); err != nil {
				return errors.Wrap(err, "discover fortinet advisory")
			}
			return nil
		},
	}

	return cmd
}
