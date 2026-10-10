package stun

import (
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, a := range []string{"203.0.113.20:40000", "[2001:db8::1]:3478"} {
		want := netip.MustParseAddrPort(a)
		_, tid := Request()
		got, err := Parse(Response(tid, want), tid)
		if err != nil || got != want {
			t.Fatalf("%s: 得到 %v %v", a, got, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	_, tid := Request()
	resp := Response(tid, netip.MustParseAddrPort("1.2.3.4:5"))
	var other [12]byte
	if _, err := Parse(resp, other); err == nil {
		t.Error("事务 ID 不匹配时应失败")
	}
	if _, err := Parse(resp[:10], tid); err == nil {
		t.Error("响应过短时应失败")
	}
}
