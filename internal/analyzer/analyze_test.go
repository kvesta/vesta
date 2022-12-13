package analyzer

import "testing"

func TestSortSeverity(t *testing.T) {
	type args struct {
		threats []*threat
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "sort_test_1",
			args: args{threats: []*threat{{Severity: "high"}, {Severity: "low"}, {Severity: "critical"}}},
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortSeverity(tt.args.threats)
		})
	}
}
