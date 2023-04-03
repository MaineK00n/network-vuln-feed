package juniper

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdJuniper() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "juniper (<juniper security advisory HTML>)",
		Short: "discover new and updated advisories for juniper",
		Example: `$ network-vuln-feed discover juniper
$ network-vuln-feed discover juniper \"https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-Evolved-A-specific-SNMP-GET-operation-and-a-specific-CLI-commands-cause-resources-to-leak-and-eventually-the-evo-pfemand-process-will-crash-CVE-2023-22400?language=en_US\"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
