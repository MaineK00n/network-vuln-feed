package template

import "time"

type Advisory struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	References      []Reference     `json:"references"`
	Published       time.Time       `json:"published"`
	Updated         time.Time       `json:"updated"`
	AdvisoryURL     string          `json:"advisory_url"`
}

type Vulnerability struct {
	ID          string       `json:"id"`
	CVE         string       `json:"cve"`
	Description string       `json:"description"`
	Definitions []Definition `json:"definitions"`
}

type Definition struct {
	Configurations []Configurations `json:"configurations"`
	CVSSv2         *CVSS            `json:"cvssv2"`
	CVSSv3         *CVSS            `json:"cvssv3"`
	CWE            []string         `json:"cwe"`
	Impact         string           `json:"impact"`
	ExploitStatus  string           `json:"exploit_status"`
}

type Configurations struct {
	Application     []Element `json:"application,omitempty"`
	OperatingSystem []Element `json:"operating_system,omitempty"`
	Hardware        []Element `json:"hardware,omitempty"`
}

type Element struct {
	Description string     `json:"description"`
	CPE         string     `json:"cpe"`
	Affected    Expression `json:"affected"`
	FixedIn     string     `json:"fixed_in"`
}

type Expression struct {
	Eqaul        string `json:"eq"`
	GreaterThan  string `json:"gt"`
	GreaterEqaul string `json:"ge"`
	LessThan     string `json:"lt"`
	LessEqual    string `json:"le"`
}

type CVSS struct {
	BaseScore          *float64 `json:"base_score"`
	TemporalScore      *float64 `json:"temporal_score"`
	EnvironmentalScore *float64 `json:"environmental_score"`
	Vector             string   `json:"vector"`
}

type Reference struct {
	Description string `json:"description"`
	URL         string `json:"url"`
}
