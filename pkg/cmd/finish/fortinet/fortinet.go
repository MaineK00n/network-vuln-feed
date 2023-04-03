package fortinet

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/network-vuln-feed/pkg/finish/fortinet"
)

func NewCmdFortinet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fortinet <advisory path>",
		Short:   "finish the fortinet advisory",
		Example: `$ network-vuln-feed finish fortinet ./dest/fortinet/2023/FG-IR-23-001.json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := fortinet.Finish(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to finish the fortinet advisory")
			}
			fmt.Println(s)
			return nil
		},
	}

	return cmd
}
