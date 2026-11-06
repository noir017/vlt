package totp

import (
	"testing"
	"time"
)

func TestRFC6238Vector(t *testing.T) {
	// Secret "12345678901234567890" from RFC 6238, T = 59.
	cfg, err := Parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Digits = 8
	if got := cfg.Code(time.Unix(59, 0)); got != "94287082" {
		t.Fatalf("code = %s, want 94287082", got)
	}
}

func TestOTPAuthURI(t *testing.T) {
	cfg, err := Parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digits != 6 || cfg.Period != 30 || cfg.Algo != "SHA1" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	if len(cfg.Code(time.Unix(0, 0))) != 6 {
		t.Fatal("code has the wrong length")
	}
}

func TestSpacesAndPadding(t *testing.T) {
	if _, err := Parse("jbsw y3dp ehpk 3pxp===="); err != nil {
		t.Fatalf("spaced and padded secret rejected: %v", err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "otpauth://hotp/x?secret=AAA", "not-base32!!"} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}
