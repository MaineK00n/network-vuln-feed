package cisco

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdCisco() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cisco (<cisco CVRF URL>)",
		Short: "discover new and updated advisories for cisco",
		Example: `$ network-vuln-feed discover cisco
$ network-vuln-feed discover cisco https://sec.cloudapps.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/cisco-sa-ise-injection-2XbOg9Dg/cvrf/cisco-sa-ise-injection-2XbOg9Dg_cvrf.xml`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}

	return cmd
}
