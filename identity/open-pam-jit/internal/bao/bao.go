// Package bao is an OpenBao (the Linux Foundation Vault fork) secrets connector
// for open-pam-jit (Phase 3). It implements access.SecretStore against the
// OpenBao/Vault KV v2 HTTP API, with a Mock for offline dev/tests. OpenBao is
// preferred over HashiCorp Vault (BUSL) for anything we deploy.
package bao

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Mock is an in-memory SecretStore (offline default).
type Mock struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewMock returns an empty in-memory store.
func NewMock() *Mock { return &Mock{data: map[string]string{}} }

func (m *Mock) Put(name, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[name] = secret
	return nil
}

func (m *Mock) Get(name string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.data[name]
	if !ok {
		return "", errors.New("secret not found")
	}
	return s, nil
}

func (m *Mock) Delete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, name)
}

// Client is the Real OpenBao/Vault KV v2 client (token auth).
type Client struct {
	addr  string
	token string
	mount string
	http  *http.Client
}

// NewClient targets addr (e.g. http://127.0.0.1:8200) with the given token,
// using the default "secret" KV v2 mount.
func NewClient(addr, token string) *Client {
	return &Client{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		mount: "secret",
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) path(name string) string {
	return fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mount, name)
}

func (c *Client) Put(name, secret string) error {
	body, _ := json.Marshal(map[string]any{"data": map[string]string{"value": secret}})
	req, err := http.NewRequest(http.MethodPost, c.path(name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("bao: put %q failed (%d)", name, resp.StatusCode)
	}
	return nil
}

func (c *Client) Get(name string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.path(name), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("secret not found")
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("bao: get %q failed (%d)", name, resp.StatusCode)
	}
	var out struct {
		Data struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Data.Data.Value, nil
}

func (c *Client) Delete(name string) {
	req, err := http.NewRequest(http.MethodDelete, c.path(name), nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.http.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
