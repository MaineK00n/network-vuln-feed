package root

import (
	"github.com/spf13/cobra"

	discoverCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover"
	finishCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/finish"
	templateCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template"
	validateCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/validate"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "network-vuln-feed <command>",
		Short:         "network-vuln-feed",
		Long:          "network-vuln-feed: discover and collect security advisories for network devices",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(discoverCmd.NewCmdDiscover())
	cmd.AddCommand(templateCmd.NewCmdTemplate())
	cmd.AddCommand(finishCmd.NewCmdFinish())
	cmd.AddCommand(validateCmd.NewCmdValidate())

	return cmd
}
