package fortinet

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	type args struct {
		rsspath  string
		rootpath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "happy",
			args: args{
				rsspath:  "testdata/fixture/happy.xml",
				rootpath: "./testdata/fixture/fortinet",
			},
		},
		{
			name: "newone",
			args: args{
				rsspath:  "testdata/fixture/newone.xml",
				rootpath: "./testdata/fixture/fortinet",
			},
			wantErr: errors.New("discover new advisory: [\"FG-IR-00-000\"]"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.args.rsspath)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			if err := Discover(u, tt.args.rootpath); ((err != nil) != (tt.wantErr != nil)) && errors.Is(err, tt.wantErr) {
				t.Errorf("Discover() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
