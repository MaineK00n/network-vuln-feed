package finish

import (
	"github.com/spf13/cobra"

	fortinetCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/finish/fortinet"
)

func NewCmdFinish() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "finish <vendor>",
		Short: "finish the advisory",
	}

	cmd.AddCommand(fortinetCmd.NewCmdFortinet())

	return cmd
}
