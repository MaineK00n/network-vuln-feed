package fortinet

import "time"

type Advisory struct {
	ID              string          `json:"id,omitempty"`
	Title           string          `json:"title,omitempty"`
	Summary         string          `json:"summary,omitempty"`
	Description     string          `json:"description,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	References      []Reference     `json:"references,omitempty"`
	Published       time.Time       `json:"published,omitempty"`
	Updated         time.Time       `json:"updated,omitempty"`
	AdvisoryURL     string          `json:"advisory_url,omitempty"`
}

type Vulnerability struct {
	ID          string       `json:"id,omitempty"`
	CVE         string       `json:"cve,omitempty"`
	Definitions []Definition `json:"definitions,omitempty"`
}

type Definition struct {
	Configurations []Configurations `json:"configurations"`
	CVSSv2         *CVSS            `json:"cvssv2,omitempty"`
	CVSSv3         *CVSS            `json:"cvssv3,omitempty"`
	CWE            []string         `json:"cwe,omitempty"`
	Impact         string           `json:"impact,omitempty"`
	ExploitStatus  string           `json:"exploit_status,omitempty"`
}

type Configurations struct {
	Nodes    []Element       `json:"nodes,omitempty"`
	Children *Configurations `json:"children,omitempty"`
}

type Element struct {
	Description string     `json:"description,omitempty"`
	CPE         string     `json:"cpe,omitempty"`
	Affected    Expression `json:"affected,omitempty"`
	FixedIn     []string   `json:"fixed_in,omitempty"`
}

type Expression struct {
	Eqaul        *string `json:"eq,omitempty"`
	GreaterThan  *string `json:"gt,omitempty"`
	GreaterEqaul *string `json:"ge,omitempty"`
	LessThan     *string `json:"lt,omitempty"`
	LessEqual    *string `json:"le,omitempty"`
}

type CVSS struct {
	BaseScore          *float64 `json:"base_score,omitempty"`
	TemporalScore      *float64 `json:"temporal_score,omitempty"`
	EnvironmentalScore *float64 `json:"environmental_score,omitempty"`
	Vector             string   `json:"vector,omitempty"`
}

type Reference struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}
