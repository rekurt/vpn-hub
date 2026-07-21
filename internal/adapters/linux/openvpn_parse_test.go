package linux

import "testing"

// parseOpenVPNState must never return a stage read off a line that has not fully
// arrived: a fragmented socket read can end mid-line ("...,CONN"), and treating that
// as the stage would mark a healthy tunnel unhealthy.
func TestParseOpenVPNState(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		output    string
		want      string
		wantError bool
	}{
		"complete state line with END": {
			output: ">INFO:OpenVPN Management Interface\n1699999999,CONNECTED,SUCCESS,10.8.0.2,,\nEND\n",
			want:   "CONNECTED",
		},
		"state line terminated by newline, END not yet arrived": {
			output: "1699999999,CONNECTED,SUCCESS,10.8.0.2,,\n",
			want:   "CONNECTED",
		},
		"truncated state line without a newline is not parsed": {
			output:    "1699999999,CONN",
			wantError: true,
		},
		"banner only": {
			output:    ">INFO:OpenVPN Management Interface\n",
			wantError: true,
		},
		"truncated after the greeting is not mistaken for a stage": {
			output:    ">INFO:hello\n1699999999,RECONNEC",
			wantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := parseOpenVPNState(test.output)
			if test.wantError {
				if err == nil {
					t.Fatalf("parseOpenVPNState(%q) = %q, want an error", test.output, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOpenVPNState(%q) unexpected error: %v", test.output, err)
			}
			if got != test.want {
				t.Fatalf("parseOpenVPNState(%q) = %q, want %q", test.output, got, test.want)
			}
		})
	}
}
