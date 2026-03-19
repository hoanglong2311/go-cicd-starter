package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers   http.Header
		wantKey   string
		wantError string
	}{
		"no authorization header": {
			headers:   http.Header{},
			wantKey:   "",
			wantError: "no authorization header included",
		},
		"empty authorization header": {
			headers:   http.Header{"Authorization": {""}},
			wantKey:   "",
			wantError: "no authorization header included",
		},
		"malformed header missing scheme": {
			headers:   http.Header{"Authorization": {"singletoken"}},
			wantKey:   "",
			wantError: "malformed authorization header",
		},
		"wrong auth scheme Bearer": {
			headers:   http.Header{"Authorization": {"Bearer some-token"}},
			wantKey:   "",
			wantError: "malformed authorization header",
		},
		"wrong auth scheme Basic": {
			headers:   http.Header{"Authorization": {"Basic abc123"}},
			wantKey:   "",
			wantError: "malformed authorization header",
		},
		"valid ApiKey header": {
			headers:   http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey:   "my-secret-key",
			wantError: "",
		},
		"valid ApiKey with complex value": {
			headers:   http.Header{"Authorization": {"ApiKey a1b2c3d4-e5f6-7890-abcd-ef1234567890"}},
			wantKey:   "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantError: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if tc.wantError != "" {
				if gotErr == nil {
					t.Fatalf("expected error %q, got nil", tc.wantError)
				}
				if gotErr.Error() != tc.wantError {
					t.Fatalf("expected error %q, got %q", tc.wantError, gotErr.Error())
				}
				return
			}

			if gotErr != nil {
				t.Fatalf("expected no error, got %q", gotErr.Error())
			}
			if gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}
		})
	}
}
