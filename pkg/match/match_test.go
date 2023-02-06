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
			args: args{s: "selemium"},
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
