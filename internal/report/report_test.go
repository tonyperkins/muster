package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   int
	}{
		{
			name:   "empty result passes",
			result: Result{},
			want:   ExitPass,
		},
		{
			name: "all required pass",
			result: Result{Checks: []Check{
				{Name: "nonroot", Required: true, Status: StatusPass},
				{Name: "signature", Required: true, Status: StatusPresent},
				{Name: "sbom", Required: true, Status: StatusPresent},
			}},
			want: ExitPass,
		},
		{
			name: "required fail gates",
			result: Result{Checks: []Check{
				{Name: "nonroot", Required: true, Status: StatusFail},
			}},
			want: ExitPolicyFailure,
		},
		{
			name: "required absent gates",
			result: Result{Checks: []Check{
				{Name: "signature", Required: true, Status: StatusAbsent},
			}},
			want: ExitPolicyFailure,
		},
		{
			name: "optional fail does not gate",
			result: Result{Checks: []Check{
				{Name: "nonroot", Required: false, Status: StatusFail},
				{Name: "signature", Required: false, Status: StatusAbsent},
			}},
			want: ExitPass,
		},
		{
			name: "skipped never gates",
			result: Result{Checks: []Check{
				{Name: "signature", Required: true, Status: StatusSkipped},
			}},
			want: ExitPass,
		},
		{
			name: "operational error wins over pass",
			result: Result{
				OperationalError: "ref not found",
				Checks:           []Check{{Name: "nonroot", Required: true, Status: StatusPass}},
			},
			want: ExitOperationalError,
		},
		{
			name: "operational error wins over policy failure",
			result: Result{
				OperationalError: "auth failed",
				Checks:           []Check{{Name: "nonroot", Required: true, Status: StatusFail}},
			},
			want: ExitOperationalError,
		},
		{
			name: "mixed: one required failure among passes gates",
			result: Result{Checks: []Check{
				{Name: "nonroot", Required: true, Status: StatusPass},
				{Name: "signature", Required: true, Status: StatusPresent},
				{Name: "sbom", Required: true, Status: StatusAbsent},
			}},
			want: ExitPolicyFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ExitCode(); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	r := Result{
		Image:  "example.com/img:latest",
		Digest: "sha256:abc",
		Checks: []Check{{Name: "nonroot", Required: true, Status: StatusPass, Detail: "ok"}},
	}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var back Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Image != r.Image || back.Digest != r.Digest || len(back.Checks) != 1 {
		t.Errorf("round trip mismatch: %+v", back)
	}
}

func TestWriteTextContainsResult(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want string
	}{
		{"pass", Result{Checks: []Check{{Name: "nonroot", Required: true, Status: StatusPass}}}, "result: PASS"},
		{"fail", Result{Checks: []Check{{Name: "nonroot", Required: true, Status: StatusFail}}}, "result: FAIL"},
		{"error", Result{OperationalError: "boom"}, "result: ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.res.WriteText(&buf); err != nil {
				t.Fatalf("WriteText: %v", err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output missing %q:\n%s", tt.want, buf.String())
			}
		})
	}
}
