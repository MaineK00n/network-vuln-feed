package discover

import (
	"github.com/spf13/cobra"

	aristaCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/arista"
	ciscoCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/cisco"
	fortinetCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/fortinet"
	juniperCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/juniper"
	necCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/nec"
	paloaltoCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/paloalto"
	yamahaCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/discover/yamaha"
)

type DiscoverOptions struct {
	Direcotry string
}

func NewCmdDiscover() *cobra.Command {
	opts := &DiscoverOptions{
		Direcotry: "",
	}

	cmd := &cobra.Command{
		Use:   "discover <vendor>",
		Short: "discover new and updated advisories",
	}

	cmd.AddCommand(aristaCmd.NewCmdArista())
	cmd.AddCommand(ciscoCmd.NewCmdCisco())
	cmd.AddCommand(fortinetCmd.NewCmdFortinet())
	cmd.AddCommand(juniperCmd.NewCmdJuniper())
	cmd.AddCommand(necCmd.NewCmdNEC())
	cmd.AddCommand(paloaltoCmd.NewCmdPaloAlto())
	cmd.AddCommand(yamahaCmd.NewCmdYAMAHA())

	cmd.Flags().StringVarP(&opts.Direcotry, "directory", "d", "", "vuls format advisory storage directory path")

	return cmd
}
