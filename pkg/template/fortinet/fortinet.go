package fortinet

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/network-vuln-feed/pkg/template"
)

func Template(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.Wrapf(err, "failed to open %s", path)
	}
	defer f.Close()

	var c cvrf
	if err := xml.NewDecoder(f).Decode(&c); err != nil {
		return "", errors.Wrap(err, "failed to decode")
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(fill(c)); err != nil {
		return "", errors.Wrap(err, "failed to encode")
	}

	return buf.String(), nil
}

func fill(c cvrf) template.Advisory {
	var a template.Advisory

	a.ID = c.DocumentTracking.Identification.ID
	if a.ID == "" {
		log.Printf("WARN: Advisory ID is unknown. (DocumentTracking>Identification>ID)")
	}
	a.AdvisoryURL = fmt.Sprintf("https://www.fortiguard.com/psirt/%s", a.ID)

	a.Title = c.DocumentTitle
	if a.Title == "" {
		log.Printf("WARN: Advisory Title is unknown. (DocumentTitle)")
	}

	var (
		impact, exploitStatus string
		css                   []template.Configurations
	)
	for _, n := range c.DocumentNotes.Note {
		switch n.Title {
		case "Summary":
			a.Summary = strings.TrimSpace(n.Text)
		case "Description":
			a.Description = strings.TrimSpace(n.Text)
		case "Impact":
			impact = strings.TrimSpace(n.Text)
		case "Explot Status":
			exploitStatus = strings.TrimSpace(n.Text)
		case "Affected Products":
			if strings.Contains(strings.ToLower(n.Text), "fortiadc") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiADC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiadc:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiADC: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiADC: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiadc-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiADC Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiai") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAI: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiai:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAI: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiai:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAI: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiai-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAIOps: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortianalyzer") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAnalyzer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAnalyzer: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAnalyzer: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortianalyzer-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAnalyzer-BigData: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAnalyzer-BigData: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAnalyzer-BigData: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortianalyzer-bigdata-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAnalyzer Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiap") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAP: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiap-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-C: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-C: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAP-C: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiap-c:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-S: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-S: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAP-S: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiap-s:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-U: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-U: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAP-U: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiap-u:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-W2: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-W2: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAP-W2: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiap-w2:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiauthenticator") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAuthenticator: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAuthenticator: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiAuthenticator: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiauthenticator-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortibalancer") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiBalancer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiBalancer: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiBalancer: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortibalancer-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortibridge") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiBridge: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortibridge:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiBridge: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortibridge:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiBridge: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortibridge-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticache") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCache: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCache: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiCache: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:forticache-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticamera") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCamera: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCamera: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiCamera: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:forticamera-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticarrier") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCarrier: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticarrier:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCarrier: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:forticarrier:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiCarrier: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:forticarrier-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticasb") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCASB: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticentral") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCentral: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticentral:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticlient") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{
							{
								Description: "FortiClient for Windows: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*",
							},
							{
								Description: "FortiClient for MacOS: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*",
							},
							{
								Description: "FortiClient for MacOSX: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*",
							},
							{
								Description: "FortiClient for Linux: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:linux:*:*",
							},
							{
								Description: "FortiClient for iOS: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:ios:*:*",
							},
							{
								Description: "FortiClient for Android: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:android:*:*",
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiClient SSL VPN: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiClientEMS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiClient Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticloud") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticonnect") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiConnect: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticonnect:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticonverter") || strings.Contains(strings.ToLower(n.Text), "forticonvertor") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiConverter: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticore") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCore: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticore:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCore: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:forticore:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiCore: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:forticore-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticwp") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCWP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticwp:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidb") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDB: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDB: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDB: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortidb-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiddos") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDDoS: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS-F: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS-F: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDDoS-F: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS-CM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS-CM: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDDoS-CM: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortideceptor") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDeceptor: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDeceptor: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDeceptor: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortideceptor-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidevsec") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDevSec: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidevsec:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidirector") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDirector: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidirector:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidns") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDNS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidns:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDNS: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortidns:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiDNS: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortidns-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiedge") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiEdge: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedge:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiEdge: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiedge:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiEdge: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiedge-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiedr") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiEDR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiEDR Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedr_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiexplorer") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiExplorer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiextender") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiExtender: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiExtender: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiExtender: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiextender-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiExtender Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiextender_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortifone") || strings.Contains(strings.ToLower(n.Text), "fortiphone") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiFone: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortifone:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiFone: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiFone: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortifone-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortigate") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiGate: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigate:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiGate: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiGate Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigate_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortigslb") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiGSLB Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigslb_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiguard") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiGuard: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiguard:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiguest") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiGuest: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiinsight") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiInsight: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiinsight:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiisolator") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiIsolator: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiIsolator: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiIsolator: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiisolator-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortilan") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiLAN Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortilan_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimail") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMail: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMail: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiMail: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortimail-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMail Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimail_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimanager") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiManager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiManager: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiManager: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortimanager-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiManager Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimom") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMoM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimom:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMoM: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortimom:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiMoM: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortimom-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimonitor") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMonitor: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMonitor: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiMonitor: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortimonitor-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortinac") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiNAC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiNAC: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiNAC: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortinac-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortindr") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiNDR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiNDR: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiNDR: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortindr-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortios") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiOS: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS-6K7K: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS-6K7K: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiOS-6K7K: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipam") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPAM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipentest") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPenTest: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipentest:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiphish") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPhish: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiphish:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPhish Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiphish_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiplanner") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPlanner: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiplanner:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipolicy") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPolicy: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipolicy:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiportal") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPortal: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipresence") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPresence: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiprivatecloud") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiPrivateCloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiprivatecloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiproxy") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiProxy: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiProxy: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiProxy: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiproxy-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortirecorder") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiRecorder: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiRecorder: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiRecorder: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortirecorder-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisandbox") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSandbox: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSandbox: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiSandbox: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortisandbox-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSandbox Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisase") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSASE: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisdnconnector") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSDNConnector: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisiem") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSIEM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSIEM: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiSIEM: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortisiem-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSIEMWindowsAgent: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisiem_windows_agent:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisoar") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSOAR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiswitch") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSwitch: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSwitch: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiSwitch: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiswitch-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSwitch Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch_manager:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSwitch Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortitester") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiTester: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiTester: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiTester: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortitester-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortitoken") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{
							{
								Description: "FortiTokenAndroid: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:android:*:*",
							},
							{
								Description: "FortiTokenIOS: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:ios:*:*",
							},
							{
								Description: "FortiTokenMobileWP: (<expression> <version>)",
								CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:windows:*:*",
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiToken Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitoken_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiview") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiView: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiview:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortivoice") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiVoice Enterprise: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiVoice Enterprise: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiVoice Enterprise: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortivoice-:-:*:*:*:entreprise:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiVoice Cloud Unified Communications: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwan") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWAN: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWAN: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiWAN: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiwan-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWAN Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiweb") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWeb: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWeb: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiWeb: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiweb-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWeb Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWeb Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwifi") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWiFi: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwifi:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiWiFi: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiwifi-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwlc") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWLC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWLC: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiWLC: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiwlc-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwlm") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWLM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWLM: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "FortiWLM: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:fortiwlm-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "av engine") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "AV Engine: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fsso") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{
							{
								Description: "FSSO",
								CPE:         "cpe:2.3:a:fortinet:fortinet_single_sign-on:*:*:*:*:*:*:*:*",
							},
							{
								Description: "FSSO CA",
								CPE:         "cpe:2.3:a:fortinet:fsso_ca:*:*:*:*:*:*:*:*",
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "ascenlink") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "AscenLink: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "AscenLink: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "AscenLink: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:al-:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "meru ap") || strings.Contains(strings.ToLower(n.Text), "meruap") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "Meru AP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "Meru AP: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:meru:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "Meru AP: (<expression> <version>)",
									CPE:         "cpe:2.3:h:fortinet:meru:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "meru controller") {
				css = append(css,
					template.Configurations{
						Nodes: []template.Element{{
							Description: "Meru Controller: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:meru_controller:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "Meru Controller: (<expression> <version>)",
								CPE:         "cpe:2.3:o:fortinet:meru_controller:*:*:*:*:*:*:*:*",
							}},
							Children: &template.Configurations{
								Nodes: []template.Element{{
									Description: "Meru Controller: (<expression> <version>)",
									CPE:         "cpe:2.3:h:meru:mc:-:*:*:*:*:*:*:*",
									Affected: template.Expression{
										Eqaul: "NA",
									},
								}},
							},
						},
					},
				)
			}
		case "Solutions":
		case "Acknowledgement":
		default:
			log.Printf("WARN: DocumentNotes>Note>Title:%s is unknown", n.Title)
		}
	}

	for _, r := range c.DocumentReferences.Reference {
		a.References = append(a.References, template.Reference{
			Description: r.Description,
			URL:         r.URL,
		})
	}

	if t, err := time.Parse("2006-01-02T00:00:00", c.DocumentTracking.CurrentReleaseDate); err != nil {
		log.Printf("WARN: Advisory Published and Updated is unknown. (DocumentTracking>CurrentReleaseDate)")
	} else {
		a.Published = t
		a.Updated = t
	}

	for _, b := range c.ProductTree.Branch.Branch {
		if b.Type != "Product Name" {
			continue
		}
		switch b.Name {
		case "FortiADC":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiADC: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiadc:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiADC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiADC: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiadc-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiADC Manager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiAI":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAI: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiai:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAI: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiai:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAI: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiai-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAIOps: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiAnalyzer":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAnalyzer: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAnalyzer: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAnalyzer: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortianalyzer-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAnalyzer-BigData: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAnalyzer-BigData: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAnalyzer-BigData: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortianalyzer-bigdata-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAnalyzer Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiAP":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiap-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP-C: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-C: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-C: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiap-c:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP-S: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-S: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-S: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiap-s:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP-U: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-U: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-U: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiap-u:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP-W2: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAP-W2: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAP-W2: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiap-w2:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAP Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiap_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiAuthenticator":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiAuthenticator: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiAuthenticator: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiAuthenticator: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiauthenticator-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiBalancer":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiBalancer: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiBalancer: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiBalancer: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortibalancer-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiBridge":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiBridge: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortibridge:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiBridge: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortibridge:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiBridge: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortibridge-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiCache":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCache: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCache: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCache: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:forticache-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiCamera":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCamera: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCamera: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCamera: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:forticamera-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiCarrier":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCarrier: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticarrier:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCarrier: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticarrier:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCarrier: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:forticarrier-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiCASB":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCASB: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiCentral":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCentral: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticentral:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiClient":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FortiClient for Windows: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*",
						},
						{
							Description: "FortiClient for MacOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*",
						},
						{
							Description: "FortiClient for MacOSX: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*",
						},
						{
							Description: "FortiClient for Linux: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:linux:*:*",
						},
						{
							Description: "FortiClient for iOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:ios:*:*",
						},
						{
							Description: "FortiClient for Android: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:android:*:*",
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiClient SSL VPN: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiClientEMS: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiClient Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticlient_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiClientWindows":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FortiClient for Windows: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*",
						},
					},
				},
			)
		case "FortiClientMAC", "FortiClientMac":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FortiClient for MacOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*",
						},
						{
							Description: "FortiClient for MacOSX: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*",
						},
					},
				},
			)
		case "FortiClientLinux":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FortiClient for Linux: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:linux:*:*",
						},
					},
				},
			)
		case "FortiCloud":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiConnect":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiConnect: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticonnect:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiConverter":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiConverter: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiCore":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCore: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticore:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiCore: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticore:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiCore: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:forticore-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiCWP":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiCWP: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:forticwp:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiDB":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDB: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDB: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDB: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortidb-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiDDoS":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDDoS: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiddos:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiDDoS-F":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDDoS-F: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS-F: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS-F: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiDDoS-CM":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDDoS-CM: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDDoS-CM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDDoS-CM: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiDeceptor":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDeceptor: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDeceptor: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDeceptor: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortideceptor-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiDevSec":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDevSec: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortidevsec:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiDirector":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDirector: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortidirector:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiDLP":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDLP: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortidlp:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiDNS":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiDNS: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortidns:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiDNS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortidns:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiDNS: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortidns-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiEdge":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiEdge: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiedge:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiEdge: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiedge:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiEdge: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiedge-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiEDR":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiEDR: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiEDR Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiedr_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiExplorer":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiExplorer: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiExtender":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiExtender: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiExtender: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiExtender: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiextender-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiExtender Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiextender_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiFone", "FortiPhone":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiFone: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortifone:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiFone: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiFone: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortifone-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiGate":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiGate: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortigate:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiGate: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiGate Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortigate_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiGSLB":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiGSLB Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortigslb_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiGuard":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiGuard: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiguard:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiGuest":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiGuest: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiInsight":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiInsight: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiinsight:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiIsolator":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiIsolator: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiIsolator: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiIsolator: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiisolator-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiLAN":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiLAN Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortilan_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiMail":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiMail: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMail: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMail: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortimail-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiMail Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimail_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiManager":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiManager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiManager: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiManager: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortimanager-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiManager Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiMoM":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiMoM: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimom:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMoM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimom:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMoM: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortimom-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiMonitor":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiMonitor: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiMonitor: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiMonitor: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortimonitor-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiNAC":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiNAC: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiNAC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiNAC: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortinac-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiNAC-F":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiNAC-F: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortinac-f:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiNAC-F: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortinac-f:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiNAC-F: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortinac-f:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiNDR":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiNDR: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiNDR: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiNDR: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortindr-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiOS":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiOS: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiOS-6K7K: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS-6K7K: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiOS-6K7K: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiPAM":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPAM: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPenTest":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPenTest: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortipentest:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPhish":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPhish: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiphish:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPhish Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiphish_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPlanner":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPlanner: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiplanner:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPolicy":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPolicy: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortipolicy:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPortal":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPortal: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPresence":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPresence: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiPrivateCloud":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiPrivateCloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiprivatecloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiProxy":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiProxy: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiProxy: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiProxy: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiproxy-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiRecorder":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiRecorder: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiRecorder: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiRecorder: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortirecorder-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiSandbox":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSandbox: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSandbox: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSandbox: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortisandbox-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSandbox Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSASE":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSASE: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSDNConnector":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSDNConnector: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSIEM":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSIEM: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSIEM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSIEM: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortisiem-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSIEMWindowsAgent: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisiem_windows_agent:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSOAR":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSOAR: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSwitch":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSwitch: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiSwitch: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiSwitch: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiswitch-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSwitch Manager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiswitch_manager:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSwitch Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiswitch_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiSwitchManager":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiSwitch Manager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiswitch_manager:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiTester":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiTester: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiTester: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiTester: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortitester-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiToken":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FortiTokenAndroid: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:android:*:*",
						},
						{
							Description: "FortiTokenIOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:ios:*:*",
						},
						{
							Description: "FortiTokenMobileWP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitoken_mobile:*:*:*:*:*:windows:*:*",
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiToken Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortitoken_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiView":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiView: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiview:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiVoice":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiVoice Enterprise: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiVoice Enterprise: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiVoice Enterprise: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortivoice-:-:*:*:*:entreprise:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiVoice Cloud Unified Communications: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiWAN":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWAN: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWAN: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWAN: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiwan-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWAN Manager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiWeb":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWeb: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWeb: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWeb: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiweb-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWeb Manager: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*",
					}},
				},
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWeb Cloud: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiweb_cloud:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FortiWiFi":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWiFi: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiwifi:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWiFi: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiwifi-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiWLC":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWLC: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWLC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWLC: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiwlc-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "FortiWLM":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "FortiWLM: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "FortiWLM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "FortiWLM: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:fortiwlm-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "AV Engine":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "AV Engine: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*",
					}},
				},
			)
		case "FSSO":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{
						{
							Description: "FSSO",
							CPE:         "cpe:2.3:a:fortinet:fortinet_single_sign-on:*:*:*:*:*:*:*:*",
						},
						{
							Description: "FSSO CA",
							CPE:         "cpe:2.3:a:fortinet:fsso_ca:*:*:*:*:*:*:*:*",
						},
					},
				},
			)
		case "AscenLink":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "AscenLink: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "AscenLink: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "AscenLink: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:al-:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "Meru AP", "MeruAP":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "Meru AP: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "Meru AP: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:meru:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "Meru AP: (<expression> <version>)",
								CPE:         "cpe:2.3:h:fortinet:meru:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		case "Meru Controller":
			css = append(css,
				template.Configurations{
					Nodes: []template.Element{{
						Description: "Meru Controller: (<expression> <version>)",
						CPE:         "cpe:2.3:a:fortinet:meru_controller:*:*:*:*:*:*:*:*",
					}},
					Children: &template.Configurations{
						Nodes: []template.Element{{
							Description: "Meru Controller: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:meru_controller:*:*:*:*:*:*:*:*",
						}},
						Children: &template.Configurations{
							Nodes: []template.Element{{
								Description: "Meru Controller: (<expression> <version>)",
								CPE:         "cpe:2.3:h:meru:mc:-:*:*:*:*:*:*:*",
								Affected: template.Expression{
									Eqaul: "NA",
								},
							}},
						},
					},
				},
			)
		}
	}

	var cvssv3 *template.CVSS
	if c.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3 != "" {
		f, err := strconv.ParseFloat(c.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3, 64)
		if err == nil {
			if cvssv3 == nil {
				cvssv3 = &template.CVSS{}
			}
			cvssv3.BaseScore = &f
		}
	}
	if c.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3 != "" {
		if cvssv3 == nil {
			cvssv3 = &template.CVSS{}
		}
		cvssv3.Vector = c.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3
	}

	for _, cve := range c.Vulnerability.CVE {
		a.Vulnerabilities = append(a.Vulnerabilities, template.Vulnerability{
			ID:  a.ID,
			CVE: cve,
			Definitions: []template.Definition{
				{
					Configurations: css,
					CVSSv3:         cvssv3,
					Impact:         impact,
					ExploitStatus:  exploitStatus,
				},
			},
		})
	}
	if len(a.Vulnerabilities) == 0 {
		a.Vulnerabilities = append(a.Vulnerabilities, template.Vulnerability{
			ID: a.ID,
			Definitions: []template.Definition{
				{
					Configurations: css,
					CVSSv3:         cvssv3,
					Impact:         impact,
					ExploitStatus:  exploitStatus,
				},
			},
		})
	}

	return a
}
