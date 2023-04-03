package fortinet

type cvrf struct {
	DocumentTitle    string `xml:"DocumentTitle"`
	DocumentType     string `xml:"DocumentType"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID"`
		} `xml:"Identification"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate"`
	} `xml:"DocumentTracking"`
	DocumentNotes struct {
		Note []struct {
			Text  string `xml:",chardata"`
			Title string `xml:"Title,attr"`
			Type  string `xml:"Type,attr"`
		} `xml:"Note"`
	} `xml:"DocumentNotes"`
	DocumentReferences struct {
		Reference []struct {
			URL         string `xml:"URL"`
			Description string `xml:"Description"`
		} `xml:"Reference"`
	} `xml:"DocumentReferences"`
	Acknowledgments []struct {
		Acknowledgment struct {
			Description string `xml:"Description"`
		} `xml:"Acknowledgment"`
	} `xml:"Acknowledgments"`
	ProductTree struct {
		Branch          branch            `xml:"Branch"`
		FullProductName []fullProductName `xml:"FullProductName"`
	} `xml:"ProductTree"`
	Vulnerability struct {
		CVE           []string `xml:"CVE"`
		CVSSScoreSets struct {
			ScoreSetV3 struct {
				BaseScoreV3 string `xml:"BaseScoreV3"`
				VectorV3    string `xml:"VectorV3"`
			} `xml:"ScoreSetV3"`
		} `xml:"CVSSScoreSets"`
	} `xml:"Vulnerability"`
}

type branch struct {
	Type            string            `xml:"Type,attr"`
	Name            string            `xml:"Name,attr"`
	FullProductName []fullProductName `xml:"FullProductName"`
	Branch          []branch          `xml:"Branch"`
}

type fullProductName struct {
	Text      string `xml:",chardata"`
	ProductID string `xml:"ProductID,attr"`
}
