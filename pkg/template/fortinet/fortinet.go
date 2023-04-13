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
						Application: []template.Element{{
							Description: "FortiADC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiadc:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiADC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiadc:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiADC: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiadc-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiADC Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiadc_manager:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiai") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAI: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiai:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAI: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiai:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAI: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiai-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAIOps: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiaiops:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortianalyzer") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAnalyzer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAnalyzer: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortianalyzer:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAnalyzer: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortianalyzer-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAnalyzer-BigData: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAnalyzer-BigData: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAnalyzer-BigData: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortianalyzer-bigdata-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAnalyzer Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortianalyzer_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiap") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAP: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAP: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiap-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP-C: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAP-C: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-c:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAP-C: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiap-c:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP-S: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAP-S: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-s:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAP-S: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiap-s:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP-U: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAP-U: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-u:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAP-U: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiap-u:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP-W2: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAP-W2: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiap-w2:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAP-W2: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiap-w2:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAP Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiap_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiauthenticator") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiAuthenticator: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiAuthenticator: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiAuthenticator: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiauthenticator-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortibalancer") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiBalancer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiBalancer: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortibalancer:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiBalancer: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortibalancer-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortibridge") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiBridge: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortibridge:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiBridge: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortibridge:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiBridge: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortibridge-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticache") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCache: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticache:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiCache: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticache:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiCache: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:forticache-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticamera") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCamera: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticamera:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiCamera: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticamera:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiCamera: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:forticamera-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticarrier") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCarrier: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticarrier:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiCarrier: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticarrier:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiCarrier: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:forticarrier-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticasb") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCASB: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticasb:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticentral") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCentral: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticentral:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticlient") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{
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
						Application: []template.Element{{
							Description: "FortiClient SSL VPN: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiClientEMS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_enterprise_management_server:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiClient Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticlient_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticloud") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticonnect") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiConnect: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticonnect:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticonverter") || strings.Contains(strings.ToLower(n.Text), "forticonvertor") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiConverter: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticonverter:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticore") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCore: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticore:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiCore: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:forticore:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiCore: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:forticore-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "forticwp") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiCWP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:forticwp:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidb") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDB: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidb:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDB: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortidb:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDB: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortidb-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiddos") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDDoS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDDoS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDDoS: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDDoS-F: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDDoS-F: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos-f:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDDoS-F: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDDoS-CM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDDoS-CM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiddos-cm:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDDoS-CM: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiddos-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortideceptor") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDeceptor: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDeceptor: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortideceptor:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDeceptor: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortideceptor-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidevsec") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDevSec: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidevsec:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidirector") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDirector: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidirector:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortidns") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiDNS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortidns:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiDNS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortidns:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiDNS: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortidns-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiedge") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiEdge: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedge:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiEdge: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiedge:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiEdge: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiedge-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiedr") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiEDR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiEDR Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiedr_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiexplorer") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiExplorer: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiexplorer:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiextender") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiExtender: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiextender:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiExtender: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiextender:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiExtender: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiextender-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiExtender Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiextender_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortifone") || strings.Contains(strings.ToLower(n.Text), "fortiphone") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiFone: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortifone:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiFone: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortifone:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiFone: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortifone-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortigate") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiGate: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigate:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiGate: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiGate Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigate_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortigslb") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiGSLB Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortigslb_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiguard") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiGuard: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiguard:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiguest") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiGuest: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiguest:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiinsight") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiInsight: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiinsight:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiisolator") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiIsolator: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiIsolator: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiIsolator: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiisolator-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortilan") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiLAN Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortilan_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimail") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiMail: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiMail: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimail:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiMail: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortimail-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiMail Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimail_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimanager") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiManager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiManager: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimanager:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiManager: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortimanager-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiManager Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimom") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiMoM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimom:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiMoM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimom:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiMoM: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortimom-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortimonitor") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiMonitor: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiMonitor: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortimonitor:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiMonitor: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortimonitor-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortinac") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiNAC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortinac:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiNAC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortinac:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiNAC: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortinac-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortindr") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiNDR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortindr:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiNDR: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortindr:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiNDR: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortindr-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortios") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiOS-6K7K: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiOS-6K7K: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios-6k7k:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiOS-6K7K: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortigate-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipam") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPAM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipentest") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPenTest: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipentest:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiphish") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPhish: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiphish:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPhish Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiphish_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiplanner") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPlanner: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiplanner:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipolicy") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPolicy: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipolicy:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiportal") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPortal: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortipresence") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPresence: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortipresence:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiprivatecloud") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiPrivateCloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiprivatecloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiproxy") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiProxy: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiProxy: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiProxy: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiproxy-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortirecorder") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiRecorder: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiRecorder: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortirecorder:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiRecorder: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortirecorder-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisandbox") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSandbox: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiSandbox: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiSandbox: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortisandbox-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSandbox Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisandbox_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisase") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSASE: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisdnconnector") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSDNConnector: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisdnconnector:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisiem") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSIEM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiSIEM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortisiem:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiSIEM: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortisiem-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSIEMWindowsAgent: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisiem_windows_agent:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortisoar") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSOAR: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiswitch") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSwitch: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiSwitch: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiSwitch: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiswitch-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSwitch Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch_manager:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiSwitch Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiswitch_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortitester") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiTester: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitester:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiTester: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortitester:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiTester: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortitester-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortitoken") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{
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
						Application: []template.Element{{
							Description: "FortiToken Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortitoken_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiview") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiView: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiview:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortivoice") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiVoice Enterprise: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiVoice Enterprise: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortivoice:*:*:*:*:entreprise:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiVoice Enterprise: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortivoice-:-:*:*:*:entreprise:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiVoice Cloud Unified Communications: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortivoice_cloud_unified_communications:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwan") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWAN: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwan:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiWAN: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwan:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiWAN: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiwan-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWAN Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwan_manager:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiweb") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWeb: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiWeb: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiweb:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiWeb: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiweb-:-:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWeb Manager: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb_manager:*:*:*:*:*:*:*:*",
						}},
					},
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWeb Cloud: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiweb_cloud:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwifi") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWiFi: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwifi:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiOS: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiWiFi: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiwifi-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwlc") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWLC: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiWLC: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwlc:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiWLC: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiwlc-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fortiwlm") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "FortiWLM: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "FortiWLM: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:fortiwlm:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "FortiWLM: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:fortiwlm-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "av engine") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "AV Engine: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:antivirus_engine:*:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "fsso") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{
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
						Application: []template.Element{{
							Description: "AscenLink: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:ascenlink:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "AscenLink: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:ascenlink:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "AscenLink: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:al-:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "meru ap") || strings.Contains(strings.ToLower(n.Text), "meruap") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "Meru AP: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:meru:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "Meru AP: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:meru:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "Meru AP: (<expression> <version>)",
							CPE:         "cpe:2.3:h:fortinet:meru:-:*:*:*:*:*:*:*",
						}},
					},
				)
			}
			if strings.Contains(strings.ToLower(n.Text), "meru controller") {
				css = append(css,
					template.Configurations{
						Application: []template.Element{{
							Description: "Meru Controller: (<expression> <version>)",
							CPE:         "cpe:2.3:a:fortinet:meru_controller:*:*:*:*:*:*:*:*",
						}},
						OperatingSystem: []template.Element{{
							Description: "Meru Controller: (<expression> <version>)",
							CPE:         "cpe:2.3:o:fortinet:meru_controller:*:*:*:*:*:*:*:*",
						}},
						Hardware: []template.Element{{
							Description: "Meru Controller: (<expression> <version>)",
							CPE:         "cpe:2.3:h:meru:mc:-:*:*:*:*:*:*:*",
						}},
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
