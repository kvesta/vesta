package analyzer

import (
	"reflect"
	"testing"
)

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

func TestWeakPassword(t *testing.T) {
	type args struct {
		p string
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "weakPassword",
			args: args{p: "root"},
			want: "Weak",
		},
		{
			name: "weakPassword",
			args: args{p: "Password123"},
			want: "Weak",
		},
		{
			name: "strongPassword",
			args: args{p: "dDjwC3m^BFXz6B#a"},
			want: "Strong",
		},
		{
			name: "mediumPassword",
			args: args{p: "plDAYh"},
			want: "Medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkWeakPassword(tt.args.p)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkWeakPassword() got = %v, want %v", got, tt.want)
			}
		})
	}

}
