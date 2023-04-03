package validate_test

import (
	"testing"

	"github.com/MaineK00n/network-vuln-feed/pkg/validate"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		wantErr bool
	}{
		{
			name:    "happy",
			args:    "./testdata/fixture/happy.json",
			wantErr: false,
		},
		{
			name:    "invalid",
			args:    "./testdata/fixture/invalid.json",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validate.Validate(tt.args); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
