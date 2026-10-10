// Package health 跟踪每个代理的健康状态，并据此决定出口节点的顺序。
package health

import (
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

// Status 是单个代理的健康状态。
type Status struct {
	Healthy    bool      `json:"healthy"`
	Known      bool      `json:"known"` // 是否至少检查过一次
	ConsecFail int       `json:"consecFail"`
	ConsecOK   int       `json:"consecOk"`
	LatencyMs  int64     `json:"latencyMs"`
	LastError  string    `json:"lastError,omitempty"`
	LastCheck  time.Time `json:"lastCheck"`
	LastChange time.Time `json:"lastChange"`
}

// Observe 记录一次检查结果并返回新状态。连续失败 failT 次判定为不健康，
// 不健康后连续成功 recT 次才判定恢复，避免抖动导致出口 IP 来回切换。
func Observe(prev Status, ok bool, latency time.Duration, errStr string, failT, recT int, now time.Time) Status {
	s := prev
	s.LastCheck = now
	if !s.Known {
		// 首次检查：直接采用结果，未检查过的代理默认视为健康。
		s.Known = true
		s.Healthy = true
	}
	if ok {
		s.ConsecOK++
		s.ConsecFail = 0
		s.LatencyMs = latency.Milliseconds()
		s.LastError = ""
		if !s.Healthy && s.ConsecOK >= recT {
			s.Healthy = true
			s.LastChange = now
		}
	} else {
		s.ConsecFail++
		s.ConsecOK = 0
		s.LastError = errStr
		if s.Healthy && s.ConsecFail >= failT {
			s.Healthy = false
			s.LastChange = now
		}
	}
	return s
}

// IsUp 判断代理是否可用（尚未检查过的视为可用）。
func IsUp(m map[string]Status, id string) bool {
	s, ok := m[id]
	return !ok || !s.Known || s.Healthy
}

// Order 根据策略和健康状态计算 hop 中真实节点的顺序。
//   - 固定模式：只有选定的代理，不论健康与否（健康状态只用于告警）。
//   - 主备模式：已启用且健康的代理按优先级排列；关闭自动回切时，
//     当前正在使用的代理只要仍健康就保持在首位，出口 IP 不会因为高优先级代理恢复而改变。
//
// 第二个返回值表示是否“全部不可用”。
func Order(st model.State, m map[string]Status, current string) ([]model.Proxy, bool) {
	enabled := st.EnabledProxies()
	if st.Policy.Mode == model.ModeFixed {
		for _, p := range enabled {
			if p.ID == st.Policy.ActiveProxyID {
				return []model.Proxy{p}, !IsUp(m, p.ID)
			}
		}
		return nil, true
	}
	var up []model.Proxy
	for _, p := range enabled {
		if IsUp(m, p.ID) {
			up = append(up, p)
		}
	}
	if !st.Policy.Failback && current != "" {
		for i, p := range up {
			if p.ID == current && i > 0 {
				up = append([]model.Proxy{p}, append(up[:i:i], up[i+1:]...)...)
				break
			}
		}
	}
	return up, len(up) == 0
}
