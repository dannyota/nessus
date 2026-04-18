package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"danny.vn/nessus"
)

const outputRoot = "examples/basic/output"

type config struct {
	Address     string `json:"address"`
	AccessKey   string `json:"access_key"`
	SecretKey   string `json:"secret_key"`
	InsecureTLS bool   `json:"insecure_tls"`
}

type rawOutput struct {
	Operation  string          `json:"operation"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	StatusCode int             `json:"statusCode"`
	Body       json.RawMessage `json:"body,omitempty"`
	BodyText   string          `json:"bodyText,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type sdkOutput struct {
	Operation string `json:"operation"`
	Count     int    `json:"count"`
	Items     any    `json:"items,omitempty"`
	Error     string `json:"error,omitempty"`
}

type compareOutput struct {
	Operation    string   `json:"operation"`
	RawItemKeys  []string `json:"rawItemKeys,omitempty"`
	SDKItemKeys  []string `json:"sdkItemKeys,omitempty"`
	UnmappedKeys []string `json:"unmappedKeys,omitempty"`
	Comparable   bool     `json:"comparable"`
	RawPath      string   `json:"rawPath"`
	SDKPath      string   `json:"sdkPath"`
	Note         string   `json:"note,omitempty"`
}

func main() {
	ctx := context.Background()

	configPath := flag.String("config", ".nessus.json", "path to config JSON")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		exitf("load config: %v", err)
	}
	if err := os.RemoveAll(outputRoot); err != nil {
		exitf("clear output: %v", err)
	}

	opts := []nessus.ClientOption{nessus.WithAPIKeys(cfg.AccessKey, cfg.SecretKey)}
	if cfg.InsecureTLS {
		opts = append(opts, nessus.WithInsecureTLS())
	}
	client, err := nessus.NewClient(cfg.Address, opts...)
	if err != nil {
		exitf("create client: %v", err)
	}

	rawClient := newRawClient(cfg)

	calls := []struct {
		operation string
		path      string
		rawKey    string
		run       func() (any, error)
	}{
		{
			operation: "ListAgents",
			path:      "/agents",
			rawKey:    "agents",
			run: func() (any, error) {
				var agents []nessus.Agent
				err := client.ListAgents(ctx, func(a nessus.Agent) error {
					agents = append(agents, a)
					return nil
				})
				return agents, err
			},
		},
		{
			operation: "ListAgentsWithOptions",
			path:      "/agents?limit=50&offset=0&sort_by=name&sort_order=asc",
			rawKey:    "agents",
			run: func() (any, error) {
				var agents []nessus.Agent
				err := client.ListAgentsWithOptions(ctx, &nessus.ListAgentsOptions{
					Limit:     50,
					Offset:    0,
					SortBy:    "name",
					SortOrder: "asc",
				}, func(a nessus.Agent) error {
					agents = append(agents, a)
					return nil
				})
				return agents, err
			},
		},
		{
			operation: "ListPolicies",
			path:      "/policies",
			rawKey:    "policies",
			run: func() (any, error) {
				return client.ListPolicies(ctx)
			},
		},
		{
			operation: "ListAgentGroups",
			path:      "/agent-groups",
			rawKey:    "groups",
			run: func() (any, error) {
				return client.ListAgentGroups(ctx)
			},
		},
	}

	for _, call := range calls {
		raw := rawClient.get(call.operation, call.path)
		if err := writeJSON(filepath.Join(outputRoot, "raw", outputName(call.operation)+".json"), raw); err != nil {
			exitf("write raw %s: %v", call.operation, err)
		}

		items, err := call.run()
		out := sdkOutput{
			Operation: call.operation,
			Count:     countItems(items),
			Items:     items,
		}
		if err != nil {
			out.Error = err.Error()
			out.Items = nil
			out.Count = 0
		}
		if err := writeJSON(filepath.Join(outputRoot, "sdk", outputName(call.operation)+".json"), out); err != nil {
			exitf("write sdk %s: %v", call.operation, err)
		}
		compare := compareRawSDK(call.operation, call.rawKey, raw, out)
		if err := writeJSON(filepath.Join(outputRoot, "compare", outputName(call.operation)+".json"), compare); err != nil {
			exitf("write compare %s: %v", call.operation, err)
		}
		fmt.Printf("%s: raw=%d sdk=%d\n", call.operation, raw.StatusCode, out.Count)
	}

	fmt.Println("raw output: examples/basic/output/raw")
	fmt.Println("sdk output: examples/basic/output/sdk")
	fmt.Println("compare output: examples/basic/output/compare")
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Address == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("address, access_key, and secret_key are required")
	}
	return &cfg, nil
}

type rawClient struct {
	base       string
	accessKey  string
	secretKey  string
	httpClient *http.Client
}

func newRawClient(cfg *config) *rawClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &rawClient{
		base:      strings.TrimRight(cfg.Address, "/"),
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

func (c *rawClient) get(operation, path string) rawOutput {
	out := rawOutput{
		Operation: operation,
		Method:    "GET",
		Path:      path,
	}
	req, err := http.NewRequestWithContext(context.Background(), "GET", c.base+path, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s", c.accessKey, c.secretKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	out.StatusCode = resp.StatusCode
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if json.Valid(body) {
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "", "  ") == nil {
			out.Body = pretty.Bytes()
		} else {
			out.Body = append(json.RawMessage(nil), body...)
		}
	} else {
		out.BodyText = string(body)
	}
	return out
}

func outputName(operation string) string {
	var b strings.Builder
	for i, r := range operation {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

func countItems(v any) int {
	if v == nil {
		return 0
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return 0
		}
		return 1
	}
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array || rv.Kind() == reflect.Map {
		return rv.Len()
	}
	return 1
}

func compareRawSDK(operation, rawKey string, raw rawOutput, sdk sdkOutput) compareOutput {
	out := compareOutput{
		Operation: operation,
		RawPath:   filepath.ToSlash(filepath.Join("raw", outputName(operation)+".json")),
		SDKPath:   filepath.ToSlash(filepath.Join("sdk", outputName(operation)+".json")),
	}
	if raw.Error != "" || sdk.Error != "" {
		out.Note = "raw or sdk call returned an error"
		return out
	}

	rawKeys := rawItemKeys(raw.Body, rawKey)
	sdkKeys := sdkItemKeys(sdk.Items)
	if len(rawKeys) == 0 || len(sdkKeys) == 0 {
		out.Note = "no list item shape to compare"
		return out
	}

	out.Comparable = true
	out.RawItemKeys = rawKeys
	out.SDKItemKeys = sdkKeys
	out.UnmappedKeys = diffKeys(rawKeys, sdkKeys, fieldNameAliases(operation))
	return out
}

func rawItemKeys(body json.RawMessage, key string) []string {
	var obj map[string]any
	if len(body) == 0 || json.Unmarshal(body, &obj) != nil {
		return nil
	}
	items, ok := obj[key].([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		return nil
	}
	return sortedNonNullKeys(item)
}

func sdkItemKeys(items any) []string {
	data, err := json.Marshal(items)
	if err != nil {
		return nil
	}
	var arr []map[string]any
	if json.Unmarshal(data, &arr) == nil && len(arr) > 0 {
		return sortedKeys(arr[0])
	}
	var obj map[string]any
	if json.Unmarshal(data, &obj) == nil && len(obj) > 0 {
		return sortedKeys(obj)
	}
	return nil
}

func diffKeys(rawKeys, sdkKeys []string, aliases map[string]string) []string {
	sdkSet := map[string]bool{}
	for _, key := range sdkKeys {
		sdkSet[key] = true
	}

	var missing []string
	for _, rawKey := range rawKeys {
		if sdkKey, ok := aliases[rawKey]; ok && sdkSet[sdkKey] {
			continue
		}
		if sdkSet[exportedName(rawKey)] {
			continue
		}
		missing = append(missing, rawKey)
	}
	return missing
}

func fieldNameAliases(operation string) map[string]string {
	common := map[string]string{
		"id":                     "ID",
		"uuid":                   "UUID",
		"ip":                     "IP",
		"mac_addrs":              "MACAddresses",
		"is_scap":                "IsSCAP",
		"node_id":                "NodeID",
		"owner_id":               "OwnerID",
		"plugin_feed_id":         "PluginFeedID",
		"template_uuid":          "TemplateUUID",
		"user_permissions":       "UserPermissions",
		"creation_date":          "CreationDate",
		"last_modification_date": "LastModificationDate",
	}
	if operation == "ListAgents" || operation == "ListAgentsWithOptions" {
		common["profile_uuid"] = "ProfileUUID"
	}
	return common
}

func exportedName(key string) string {
	parts := strings.Split(key, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedNonNullKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key, value := range m {
		if value == nil {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func exitf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
