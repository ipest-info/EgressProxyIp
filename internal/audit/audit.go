// Package audit 记录管理员操作与重要的系统事件。
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event 是一条审计记录。
type Event struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"` // 操作者："admin"、"system"、"health"
	Action  string    `json:"action"`
	Detail  string    `json:"detail,omitempty"`
	Success bool      `json:"success"`
}

// Log 把事件追加写入 JSONL 文件，并在内存中保留最近的若干条。
type Log struct {
	mu   sync.Mutex
	path string
	ring []Event
	next int
	full bool
}

// New 创建一个在内存中保留 size 条事件的日志，path 可以为空。
func New(path string, size int) *Log {
	return &Log{path: path, ring: make([]Event, size)}
}

// Add 记录一条事件。
func (l *Log) Add(actor, action, detail string, success bool) {
	e := Event{Time: time.Now(), Actor: actor, Action: action, Detail: detail, Success: success}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
	if l.path == "" {
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	f.Write(append(b, '\n'))
}

// Recent 按时间倒序返回事件。
func (l *Log) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.next
	if l.full {
		n = len(l.ring)
	}
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, l.ring[(l.next-i+len(l.ring))%len(l.ring)])
	}
	return out
}
