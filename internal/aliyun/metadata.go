// Package aliyun 读取阿里云 ECS 实例元数据，支持加固模式（token）。
package aliyun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultEndpoint 是 ECS 实例内元数据服务的地址。
const DefaultEndpoint = "http://100.100.100.200"

// Client 获取元数据，HTTP 客户端应带 egp 的绕过标记。
type Client struct {
	Endpoint string
	HTTP     *http.Client
}

// Info 是 egp 用到的元数据子集。
type Info struct {
	InstanceID string `json:"instanceId,omitempty"`
	RegionID   string `json:"regionId,omitempty"`
	PrivateIP  string `json:"privateIp,omitempty"`
	PublicIP   string `json:"publicIp,omitempty"` // 绑定了 EIP 时为 EIP，否则为自动分配的公网 IPv4
	VPCCIDR    string `json:"vpcCidr,omitempty"`
}

func (c *Client) endpoint() string {
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/")
	}
	return DefaultEndpoint
}

func (c *Client) token(ctx context.Context) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint()+"/latest/api/token", nil)
	req.Header.Set("X-aliyun-ecs-metadata-token-ttl-seconds", "300")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b))
}

func (c *Client) get(ctx context.Context, token, path string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint()+"/latest/meta-data/"+path, nil)
	if token != "" {
		req.Header.Set("X-aliyun-ecs-metadata-token", token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("元数据 %s: HTTP %d", path, resp.StatusCode)
	}
	return strings.TrimSpace(string(b)), nil
}

// Fetch 返回实例元数据；不在 ECS 上运行时会很快失败。
func (c *Client) Fetch(ctx context.Context) (*Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tok := c.token(ctx)
	id, err := c.get(ctx, tok, "instance-id")
	if err != nil {
		return nil, fmt.Errorf("不是阿里云 ECS 或元数据服务不可达: %w", err)
	}
	info := &Info{InstanceID: id}
	info.RegionID, _ = c.get(ctx, tok, "region-id")
	info.PrivateIP, _ = c.get(ctx, tok, "private-ipv4")
	info.VPCCIDR, _ = c.get(ctx, tok, "vpc-cidr-block")
	if ip, err := c.get(ctx, tok, "eipv4"); err == nil && ip != "" {
		info.PublicIP = ip
	} else if ip, err := c.get(ctx, tok, "public-ipv4"); err == nil {
		info.PublicIP = ip
	}
	if info.PublicIP == "" {
		return info, errors.New("实例未绑定公网 IP（可能通过 NAT 网关出网）")
	}
	return info, nil
}
