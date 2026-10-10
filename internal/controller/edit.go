package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/proxyuri"
)

// edit 在锁内修改编辑中的状态并持久化。修改只有在 Apply 后才会生效。
func (c *Controller) edit(fn func(s *model.State) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := clone(c.state)
	if err := fn(&next); err != nil {
		return err
	}
	next.FillDefaults()
	if err := c.store.Save(next); err != nil {
		return fmt.Errorf("保存状态失败: %w", err)
	}
	c.state = next
	return nil
}

func newID() string { return randomHex(4) }

// AddProxies 添加代理（ID 自动生成）。返回新增的代理。
func (c *Controller) AddProxies(ps []model.Proxy) ([]model.Proxy, error) {
	var added []model.Proxy
	err := c.edit(func(s *model.State) error {
		for _, p := range ps {
			if err := model.ValidateProxy(p); err != nil {
				return err
			}
			for _, q := range s.Proxies {
				if q.Host == p.Host && q.Port == p.Port && q.Username == p.Username {
					return fmt.Errorf("代理 %s 已存在", p.Addr())
				}
			}
			p.ID = newID()
			for s.FindProxy(p.ID) >= 0 {
				p.ID = newID()
			}
			if p.Name == "" {
				p.Name = p.Addr()
			}
			if p.UDP == "" {
				p.UDP = model.UDPUnknown
			}
			p.LastTest = nil
			s.Proxies = append(s.Proxies, p)
			added = append(added, p)
		}
		return nil
	})
	if err == nil {
		c.Audit.Add("admin", "添加代理", fmt.Sprintf("%d 个", len(added)), true)
	}
	return added, err
}

// ImportProxies 批量导入，返回导入成功的数量和逐行错误。
func (c *Controller) ImportProxies(text string) (int, []proxyuri.LineError, error) {
	ps, lineErrs := proxyuri.ParseBatch(text)
	if len(ps) == 0 {
		return 0, lineErrs, nil
	}
	// 跳过重复项而不是整体失败。
	cur := c.State()
	var fresh []model.Proxy
	for _, p := range ps {
		dup := false
		for _, q := range append(cur.Proxies, fresh...) {
			if q.Host == p.Host && q.Port == p.Port && q.Username == p.Username {
				dup = true
			}
		}
		if dup {
			lineErrs = append(lineErrs, proxyuri.LineError{Text: p.Addr(), Error: "已存在，已跳过"})
			continue
		}
		fresh = append(fresh, p)
	}
	added, err := c.AddProxies(fresh)
	return len(added), lineErrs, err
}

// ProxyPatch 是可修改的代理字段；Password 为 nil 表示不修改密码。
type ProxyPatch struct {
	Name     string  `json:"name"`
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Username string  `json:"username"`
	Password *string `json:"password"`
	Enabled  bool    `json:"enabled"`
}

// UpdateProxy 修改代理。
func (c *Controller) UpdateProxy(id string, pt ProxyPatch) error {
	return c.edit(func(s *model.State) error {
		i := s.FindProxy(id)
		if i < 0 {
			return errors.New("代理不存在")
		}
		p := s.Proxies[i]
		changedAddr := p.Host != pt.Host || p.Port != pt.Port || p.Username != pt.Username || pt.Password != nil
		p.Name, p.Host, p.Port, p.Username, p.Enabled = strings.TrimSpace(pt.Name), strings.TrimSpace(pt.Host), pt.Port, pt.Username, pt.Enabled
		if pt.Password != nil {
			p.Password = *pt.Password
		}
		if p.Username == "" {
			p.Password = ""
		}
		if p.Name == "" {
			p.Name = p.Addr()
		}
		if err := model.ValidateProxy(p); err != nil {
			return err
		}
		if changedAddr {
			// 地址或账号变了，之前的测试结果不再可信。
			p.LastTest, p.UDP = nil, model.UDPUnknown
		}
		s.Proxies[i] = p
		return nil
	})
}

// DeleteProxy 删除代理。
func (c *Controller) DeleteProxy(id string) error {
	return c.edit(func(s *model.State) error {
		i := s.FindProxy(id)
		if i < 0 {
			return errors.New("代理不存在")
		}
		s.Proxies = append(s.Proxies[:i], s.Proxies[i+1:]...)
		if s.Policy.ActiveProxyID == id {
			s.Policy.ActiveProxyID = ""
		}
		return nil
	})
}

// ReorderProxies 按给定 ID 顺序重排（即主备优先级）。
func (c *Controller) ReorderProxies(order []string) error {
	return c.edit(func(s *model.State) error {
		if len(order) != len(s.Proxies) {
			return errors.New("排序列表与代理数量不一致")
		}
		out := make([]model.Proxy, 0, len(order))
		seen := map[string]bool{}
		for _, id := range order {
			i := s.FindProxy(id)
			if i < 0 || seen[id] {
				return fmt.Errorf("无效的代理 ID %q", id)
			}
			seen[id] = true
			out = append(out, s.Proxies[i])
		}
		s.Proxies = out
		return nil
	})
}

// SetPolicy 修改出口策略。
func (c *Controller) SetPolicy(p model.Policy) error {
	return c.edit(func(s *model.State) error {
		s.Policy = p
		tmp := clone(*s)
		tmp.Enabled = false // 只校验策略本身，启用相关的检查在 Apply 时进行
		return tmp.Validate()
	})
}

// SetBypass 修改绕过规则。
func (c *Controller) SetBypass(b model.Bypass) error {
	return c.edit(func(s *model.State) error {
		for i, d := range b.Domains {
			b.Domains[i] = strings.ToLower(strings.TrimSpace(d))
		}
		for i, cidr := range b.CIDRs {
			b.CIDRs[i] = strings.TrimSpace(cidr)
		}
		s.Bypass = b
		tmp := clone(*s)
		tmp.Enabled = false
		return tmp.Validate()
	})
}

// SettingsPatch 是 WebUI 可修改的设置（不含密码）。
type SettingsPatch struct {
	Listen      string   `json:"listen"`
	GostBin     string   `json:"gostBin"`
	RedirPort   int      `json:"redirPort"`
	TProxyPort  int      `json:"tproxyPort"`
	APIPort     int      `json:"apiPort"`
	MetricsPort int      `json:"metricsPort"`
	HealthURL   string   `json:"healthUrl"`
	EchoURLs    []string `json:"echoUrls"`
	STUNServer  string   `json:"stunServer"`
}

// SetSettings 修改设置。
func (c *Controller) SetSettings(p SettingsPatch) error {
	return c.edit(func(s *model.State) error {
		st := &s.Settings
		st.Listen, st.GostBin = strings.TrimSpace(p.Listen), strings.TrimSpace(p.GostBin)
		st.RedirPort, st.TProxyPort, st.APIPort, st.MetricsPort = p.RedirPort, p.TProxyPort, p.APIPort, p.MetricsPort
		st.HealthURL, st.STUNServer = strings.TrimSpace(p.HealthURL), strings.TrimSpace(p.STUNServer)
		var urls []string
		for _, u := range p.EchoURLs {
			if u = strings.TrimSpace(u); u != "" {
				urls = append(urls, u)
			}
		}
		st.EchoURLs = urls
		tmp := clone(*s)
		tmp.Enabled = false
		return tmp.Validate()
	})
}

// SetEnabled 修改启用开关（需随后 Apply）。
func (c *Controller) SetEnabled(on bool) error {
	return c.edit(func(s *model.State) error { s.Enabled = on; return nil })
}

// SetPasswordHash 修改管理员密码哈希，立即生效且不需要 Apply。
func (c *Controller) SetPasswordHash(hash string) error {
	err := c.edit(func(s *model.State) error { s.Settings.AdminHash = hash; return nil })
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied != nil {
		c.applied.State.Settings.AdminHash = hash
		c.store.SaveApplied(c.applied)
	}
	c.Audit.Add("admin", "修改管理员密码", "", true)
	return nil
}

// TestProxy 测试代理并保存结果（UDP 能力会影响生成的 gost 配置）。
func (c *Controller) TestProxy(ctx context.Context, id string) (*model.TestResult, error) {
	st := c.State()
	i := st.FindProxy(id)
	if i < 0 {
		return nil, errors.New("代理不存在")
	}
	res := c.prober(st).Test(ctx, st.Proxies[i])
	err := c.edit(func(s *model.State) error {
		if j := s.FindProxy(id); j >= 0 {
			r := res
			s.Proxies[j].LastTest = &r
			if res.OK && res.UDP != model.UDPUnknown {
				s.Proxies[j].UDP = res.UDP
			}
		}
		return nil
	})
	return &res, err
}

// comparable 去掉不影响生效配置的字段，用于判断是否有未应用的修改。
func comparable(s model.State) string {
	s = clone(s)
	s.Settings.AdminHash = ""
	for i := range s.Proxies {
		s.Proxies[i].LastTest = nil
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// dirtyLocked 判断编辑中的状态是否与已生效的状态不同。调用方持有 c.mu。
func (c *Controller) dirtyLocked() bool {
	if c.applied == nil {
		return c.state.Enabled || len(c.state.Proxies) > 0
	}
	return comparable(c.state) != comparable(c.applied.State)
}
