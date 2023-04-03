package yamaha

import "testing"

func TestTemplate(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Template(); got != tt.want {
				t.Errorf("Template() = %v, want %v", got, tt.want)
			}
		})
	}
}
