package match

import (
	"reflect"
	"testing"
)

func TestPythonMatch(t *testing.T) {
	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    Suspicion
		wantErr bool
	}{
		{
			name: "normal",
			args: args{s: "django"},
			want: Suspicion{
				Types:      Unknown,
				OriginPack: "",
			},
		},
		{
			name: "noramlConfusion",
			args: args{s: "fastapi"},
			want: Suspicion{
				Types:      Unknown,
				OriginPack: "",
			},
		},
		{
			name: "confusion",
			args: args{s: "selenuim"},
			want: Suspicion{
				Types:      Confusion,
				OriginPack: "selenium",
			},
		},
		{
			name: "confusion2",
			args: args{s: "pilow"},
			want: Suspicion{
				Types:      Confusion,
				OriginPack: "pillow",
			},
		},
		{
			name: "malware",
			args: args{s: "smb"},
			want: Suspicion{
				Types:      Malware,
				OriginPack: "pysmb",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PyMatch(tt.args.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PyMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonNormalPackages(t *testing.T) {
	type args struct {
		s string
	}

	type TestPy struct {
		name    string
		args    args
		want    Suspicion
		wantErr bool
	}

	var tests []TestPy

	for _, p := range pypis {
		tests = append(tests, struct {
			name    string
			args    args
			want    Suspicion
			wantErr bool
		}{name: p, args: args{s: p}, want: Suspicion{
			Types:      Unknown,
			OriginPack: "",
		}})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PyMatch(tt.args.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PyMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeMatch(t *testing.T) {
	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    Suspicion
		wantErr bool
	}{
		{
			name: "confusion",
			args: args{s: "ladash"},
			want: Suspicion{
				Types:      Confusion,
				OriginPack: "lodash",
			},
		},
		{
			name: "confusion2",
			args: args{s: "socketio"},
			want: Suspicion{
				Types:      Confusion,
				OriginPack: "socket.io",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NpmMatch(tt.args.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NpmMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNpmNormalPackages(t *testing.T) {
	type args struct {
		s string
	}

	type TestNpm struct {
		name    string
		args    args
		want    Suspicion
		wantErr bool
	}

	var tests []TestNpm

	for _, p := range npms {
		tests = append(tests, struct {
			name    string
			args    args
			want    Suspicion
			wantErr bool
		}{name: p, args: args{s: p}, want: Suspicion{
			Types:      Unknown,
			OriginPack: "",
		}})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PyMatch(tt.args.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NpmMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}
