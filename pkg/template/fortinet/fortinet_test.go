package fortinet

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/network-vuln-feed/pkg/template"
)

func TestTemplate(t *testing.T) {
	tests := []struct {
		fixture string
		golden  string
		wantErr bool
	}{
		{
			fixture: "./testdata/fixture/FG-IR-23-001_cvrf.xml",
			golden:  "./testdata/golden/FG-IR-23-001.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			f, err := os.Open(tt.golden)
			if err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}
			defer f.Close()

			var want template.Advisory
			if err := json.NewDecoder(f).Decode(&want); err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			s, err := Template(tt.fixture)
			if (err != nil) != tt.wantErr {
				t.Errorf("Template() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var got template.Advisory
			if err := json.NewDecoder(strings.NewReader(s)).Decode(&got); err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("Template() is mismatch (-v1 +v2):%s\n", diff)
			}
		})
	}
}
