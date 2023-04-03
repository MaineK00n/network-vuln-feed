package juniper

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdJuniper() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "juniper <juniper security advisory HTML>",
		Short:   "create a template for a Vuls format advisory from juniper security advisory HTML",
		Example: "$ network-vuln-feed template juniper \"2023-01 Security Bulletin Junos OS Evolved A specific SNMP GET operation and a specific CLI commands cause resources to leak and eventually the evo-pfemand process will crash (CVE-2023-22400).html\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
