// Package store 以原子替换的方式把 egp 状态持久化为 JSON 文件。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

const (
	stateFile   = "state.json"
	appliedFile = "applied.json"
	pendingFile = "pending.json"
)

// Store 管理状态文件，所有方法均可并发调用。
type Store struct {
	dir string
	mu  sync.Mutex
}

// New 返回以 dir 为根目录的 Store，目录不存在时以 0700 权限创建。
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir 返回 Store 写入的目录。
func (s *Store) Dir() string { return s.dir }

// Load 读取状态；状态文件尚不存在时返回默认值。
func (s *Store) Load() (model.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := model.Default()
	ok, err := readJSON(filepath.Join(s.dir, stateFile), &st)
	if err != nil {
		return st, err
	}
	if !ok {
		st = model.Default()
	}
	st.FillDefaults()
	return st, nil
}

// Save 原子替换状态文件。
func (s *Store) Save(st model.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteJSON(filepath.Join(s.dir, stateFile), st)
}

// Applied 是最近一次成功应用并已确认的配置，回滚和开机守护都以它为准。
type Applied struct {
	State     model.State `json:"state"`
	AppliedAt time.Time   `json:"appliedAt"`
}

// Pending 标记一次尚未确认的应用。进程在待确认期间重启时，据此回滚到 Applied。
type Pending struct {
	Nonce    string    `json:"nonce"`
	Deadline time.Time `json:"deadline"`
}

// SavePending 写入或删除（p 为 nil）待确认标记。
func (s *Store) SavePending(p *Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, pendingFile)
	if p == nil {
		err := os.Remove(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return WriteJSON(path, p)
}

// LoadPending 返回待确认标记，没有时返回 nil。
func (s *Store) LoadPending() (*Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p Pending
	ok, err := readJSON(filepath.Join(s.dir, pendingFile), &p)
	if err != nil || !ok {
		return nil, err
	}
	return &p, nil
}

// LoadApplied 返回最近一次确认的配置，没有时返回 nil。
func (s *Store) LoadApplied() (*Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var a Applied
	ok, err := readJSON(filepath.Join(s.dir, appliedFile), &a)
	if err != nil || !ok {
		return nil, err
	}
	a.State.FillDefaults()
	return &a, nil
}

// SaveApplied 记录当前生效且已确认的配置；传入 nil 表示删除。
func (s *Store) SaveApplied(a *Applied) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a == nil {
		err := os.Remove(filepath.Join(s.dir, appliedFile))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return WriteJSON(filepath.Join(s.dir, appliedFile), a)
}

func readJSON(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	return true, nil
}

// WriteJSON 原子写入 v（临时文件 → fsync → rename → 目录 fsync），
// 权限为 0600，因为状态中包含代理账号密码。
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'), 0o600)
}

// WriteFile 原子写入 data。
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
