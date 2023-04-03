package template

import (
	"github.com/spf13/cobra"

	aristaCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/arista"
	ciscoCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/cisco"
	fortinetCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/fortinet"
	juniperCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/juniper"
	necCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/nec"
	paloaltoCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/paloalto"
	yamahaCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/template/yamaha"
)

func NewCmdTemplate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template <vendor>",
		Short: "create a template for a Vuls format advisory",
	}

	cmd.AddCommand(aristaCmd.NewCmdArista())
	cmd.AddCommand(ciscoCmd.NewCmdCisco())
	cmd.AddCommand(fortinetCmd.NewCmdFortinet())
	cmd.AddCommand(juniperCmd.NewCmdJuniper())
	cmd.AddCommand(necCmd.NewCmdNEC())
	cmd.AddCommand(paloaltoCmd.NewCmdPaloAlto())
	cmd.AddCommand(yamahaCmd.NewCmdYAMAHA())

	return cmd
}
