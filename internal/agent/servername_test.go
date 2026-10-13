package agent

import "testing"

func TestTLSServerName(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		want    string
		wantErr bool
	}{
		{"derived from host:port", Config{ControlAddr: "example.com:4443"}, "example.com", false},
		{"explicit override wins", Config{ControlAddr: "1.2.3.4:4443", ServerName: "example.com"}, "example.com", false},
		{"bare host", Config{ControlAddr: "example.com"}, "example.com", false},
		{"ipv6 literal", Config{ControlAddr: "[2001:db8::1]:4443"}, "2001:db8::1", false},
		{"empty host is an error", Config{ControlAddr: ":4443"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := tlsServerName(c.cfg)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
