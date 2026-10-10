package gost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// API 是 gost Web API 的客户端（只监听在 127.0.0.1）。
type API struct {
	Base     string // 例如 http://127.0.0.1:17890
	Password string
	HTTP     *http.Client
}

// NewAPI 创建 API 客户端。
func NewAPI(port int, password string) *API {
	return &API{
		Base:     "http://127.0.0.1:" + strconv.Itoa(port),
		Password: password,
		HTTP:     &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
}

func (a *API) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(APIUser, a.Password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return b, fmt.Errorf("gost API %s %s 返回 HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// Ping 检查 API 是否可用，并确认 egp 的服务已加载。
func (a *API) Ping(ctx context.Context) error {
	b, err := a.do(ctx, http.MethodGet, "/config", nil)
	if err != nil {
		return err
	}
	var cfg struct {
		Services []struct {
			Name string `json:"name"`
		} `json:"services"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("解析 gost 配置失败: %w", err)
	}
	for _, s := range cfg.Services {
		if s.Name == ServiceRedir {
			return nil
		}
	}
	return fmt.Errorf("gost 中没有找到服务 %s", ServiceRedir)
}

// UpdateHop 在运行时替换出口 hop，不会重启 gost。
func (a *API) UpdateHop(ctx context.Context, h Hop) error {
	_, err := a.do(ctx, http.MethodPut, "/config/hops/"+url.PathEscape(h.Name), h)
	return err
}

// Traffic 是从 gost 指标中汇总出的流量统计。
type Traffic struct {
	InputBytes  float64 `json:"inputBytes"`  // 客户端 → gost（上行）
	OutputBytes float64 `json:"outputBytes"` // gost → 客户端（下行）
	Requests    float64 `json:"requests"`
	InFlight    float64 `json:"inFlight"`
	Errors      float64 `json:"errors"`
}

// FetchTraffic 读取 Prometheus 格式的指标并按 egp 服务汇总。
func FetchTraffic(ctx context.Context, port int) (Traffic, error) {
	var t Traffic
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/metrics", nil)
	resp, err := (&http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return t, err
	}
	defer resp.Body.Close()
	return ParseMetrics(resp.Body), nil
}

// ParseMetrics 解析 Prometheus 文本格式中 egp 关心的几个指标。
func ParseMetrics(r io.Reader) Traffic {
	var t Traffic
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || !strings.Contains(line, `service="egp-`) {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "gost_service_transfer_input_bytes_total{"):
			t.InputBytes += v
		case strings.HasPrefix(line, "gost_service_transfer_output_bytes_total{"):
			t.OutputBytes += v
		case strings.HasPrefix(line, "gost_service_requests_total{"):
			t.Requests += v
		case strings.HasPrefix(line, "gost_service_requests_in_flight{"):
			t.InFlight += v
		case strings.HasPrefix(line, "gost_service_handler_errors_total{"):
			t.Errors += v
		}
	}
	return t
}
