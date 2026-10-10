package health

import (
	"testing"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

func TestObserveHysteresis(t *testing.T) {
	now := time.Unix(0, 0)
	var s Status
	s = Observe(s, false, 0, "x", 3, 2, now)
	if !s.Healthy {
		t.Fatal("一次失败不应判定为不健康")
	}
	s = Observe(s, false, 0, "x", 3, 2, now)
	s = Observe(s, false, 0, "x", 3, 2, now)
	if s.Healthy {
		t.Fatal("连续 3 次失败应判定为不健康")
	}
	s = Observe(s, true, time.Millisecond, "", 3, 2, now)
	if s.Healthy {
		t.Fatal("一次成功不应恢复")
	}
	s = Observe(s, true, time.Millisecond, "", 3, 2, now)
	if !s.Healthy {
		t.Fatal("连续 2 次成功应恢复")
	}
}

func TestOrder(t *testing.T) {
	st := model.Default()
	st.Proxies = []model.Proxy{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}, {ID: "c", Enabled: false}, {ID: "d", Enabled: true}}
	m := map[string]Status{"a": {Known: true, Healthy: false}}
	got, down := Order(st, m, "")
	if down || len(got) != 2 || got[0].ID != "b" || got[1].ID != "d" {
		t.Fatalf("got %v", got)
	}
	// 关闭自动回切：当前使用 d，a/b 都恢复后 d 仍在首位。
	st.Policy.Failback = false
	got, _ = Order(st, map[string]Status{}, "d")
	if got[0].ID != "d" || got[1].ID != "a" || got[2].ID != "b" {
		t.Fatalf("got %v", got)
	}
	// 全部不可用。
	all := map[string]Status{"a": {Known: true}, "b": {Known: true}, "d": {Known: true}}
	if got, down := Order(st, all, ""); !down || len(got) != 0 {
		t.Fatalf("got %v %v", got, down)
	}
	// 固定模式。
	st.Policy.Mode = model.ModeFixed
	st.Policy.ActiveProxyID = "b"
	if got, down := Order(st, all, ""); len(got) != 1 || got[0].ID != "b" || !down {
		t.Fatalf("got %v %v", got, down)
	}
}
