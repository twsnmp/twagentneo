package audit

import "testing"

func TestSeverityInt(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"warn", 2},
		{"low", 1},
		{"info", 1},
		{"unknown", 1},
	}

	for _, tt := range tests {
		if got := SeverityInt(tt.level); got != tt.want {
			t.Errorf("SeverityInt(%q) = %d, want %d", tt.level, got, tt.want)
		}
	}
}
