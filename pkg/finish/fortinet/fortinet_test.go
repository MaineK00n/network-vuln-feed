package fortinet_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/network-vuln-feed/pkg/finish/fortinet"
)

func TestFinish(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    string
		wantErr bool
	}{
		{
			name: "happy",
			args: "testdata/fixtures/happy.json",
			want: "testdata/golden/happy.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.want)
			if err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}
			defer f.Close()

			var want fortinet.Advisory
			if err := json.NewDecoder(f).Decode(&want); err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			s, err := fortinet.Finish(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Finish() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var got fortinet.Advisory
			if err := json.NewDecoder(strings.NewReader(s)).Decode(&got); err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("Finish() is mismatch (-v1 +v2):%s\n", diff)
			}
		})
	}
}
