package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
)

const (
	benchmarkKeywordCount = 500
	benchmarkTextLength   = 12000
	benchmarkAPIKey       = "sk-risk-benchmark-20260714"
)

type apiEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type authData struct {
	AccessToken string `json:"access_token"`
}

type loadResult struct {
	Scenario       string        `json:"scenario"`
	Concurrency    int           `json:"concurrency"`
	Requests       int           `json:"requests"`
	Successes      int64         `json:"successes"`
	Errors         int64         `json:"errors"`
	StatusCounts   map[int]int64 `json:"status_counts"`
	ElapsedMS      float64       `json:"elapsed_ms"`
	RequestsPerSec float64       `json:"requests_per_second"`
	AverageLatency float64       `json:"average_latency_ms"`
	P50Latency     float64       `json:"p50_latency_ms"`
	P95Latency     float64       `json:"p95_latency_ms"`
	P99Latency     float64       `json:"p99_latency_ms"`
	MaxLatency     float64       `json:"max_latency_ms"`
}

func main() {
	mode := flag.String("mode", "load", "setup or load")
	baseURL := flag.String("base-url", "http://127.0.0.1:18080", "Sub2API base URL")
	dsn := flag.String("dsn", "postgres://sub2api:risk-benchmark-password@127.0.0.1:15432/sub2api?sslmode=disable", "PostgreSQL DSN")
	adminEmail := flag.String("admin-email", "risk-benchmark@sub2api.local", "benchmark admin email")
	adminPassword := flag.String("admin-password", "RiskBenchmarkPass123!", "benchmark admin password")
	concurrency := flag.Int("concurrency", 1, "parallel requests")
	requests := flag.Int("requests", 10000, "measured requests")
	warmup := flag.Int("warmup", 500, "warm-up requests")
	scenario := flag.String("scenario", "tail_hit", "tail_hit or miss")
	flag.Parse()

	ctx := context.Background()
	var err error
	switch *mode {
	case "setup":
		err = setup(ctx, *baseURL, *dsn, *adminEmail, *adminPassword)
	case "load":
		err = runLoad(ctx, *baseURL, *scenario, *concurrency, *requests, *warmup)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setup(ctx context.Context, baseURL, dsn, email, password string) error {
	if err := waitForHealth(ctx, baseURL, 60*time.Second); err != nil {
		return err
	}
	token, err := login(ctx, baseURL, email, password)
	if err != nil {
		return err
	}
	if err := createAPIKey(ctx, baseURL, token); err != nil {
		return err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	config, err := benchmarkModerationConfig()
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO settings (key, value, updated_at)
VALUES ($1, $2, NOW()), ($3, $4, NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
		"risk_control_enabled", "true", "content_moderation_config", config); err != nil {
		return fmt.Errorf("write benchmark settings: %w", err)
	}
	fmt.Printf("setup complete: api_key=%s keywords=%d\n", benchmarkAPIKey, benchmarkKeywordCount)
	return nil
}

func waitForHealth(ctx context.Context, baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/health", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("backend health check timed out")
}

func login(ctx context.Context, baseURL, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	envelope, status, err := requestEnvelope(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v1/auth/login", "", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || envelope.Code != 0 {
		return "", fmt.Errorf("login failed: status=%d code=%d message=%s", status, envelope.Code, envelope.Message)
	}
	var data authData
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return "", err
	}
	if data.AccessToken == "" {
		return "", errors.New("login response did not contain access token")
	}
	return data.AccessToken, nil
}

func createAPIKey(ctx context.Context, baseURL, token string) error {
	body, _ := json.Marshal(map[string]any{
		"name":       "risk-benchmark",
		"custom_key": benchmarkAPIKey,
	})
	envelope, status, err := requestEnvelope(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v1/keys", token, body)
	if err != nil {
		return err
	}
	if status == http.StatusOK && envelope.Code == 0 {
		return nil
	}
	if strings.Contains(strings.ToLower(envelope.Message), "already") || strings.Contains(strings.ToLower(envelope.Message), "exist") {
		return nil
	}
	return fmt.Errorf("create API key failed: status=%d code=%d message=%s", status, envelope.Code, envelope.Message)
}

func requestEnvelope(ctx context.Context, method, url, token string, body []byte) (apiEnvelope, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return apiEnvelope{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return apiEnvelope{}, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return apiEnvelope{}, resp.StatusCode, err
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return apiEnvelope{}, resp.StatusCode, fmt.Errorf("decode response %q: %w", string(raw), err)
	}
	return envelope, resp.StatusCode, nil
}

func benchmarkModerationConfig() (string, error) {
	keywords := make([]string, benchmarkKeywordCount)
	for index := range keywords {
		keywords[index] = fmt.Sprintf("blocked-keyword-%05d-z", index)
	}
	config := map[string]any{
		"enabled":                true,
		"mode":                   "pre_block",
		"sample_rate":            100,
		"all_groups":             true,
		"record_non_hits":        false,
		"worker_count":           4,
		"queue_size":             32768,
		"block_status":           403,
		"block_message":          "blocked by risk benchmark",
		"email_on_hit":           false,
		"auto_ban_enabled":       false,
		"pre_hash_check_enabled": false,
		"blocked_keywords":       keywords,
		"keyword_blocking_mode":  "keyword_only",
		"model_filter": map[string]any{
			"type":   "all",
			"models": []string{},
		},
	}
	raw, err := json.Marshal(config)
	return string(raw), err
}

func runLoad(ctx context.Context, baseURL, scenario string, concurrency, requests, warmup int) error {
	if concurrency <= 0 || requests <= 0 || warmup < 0 {
		return errors.New("concurrency and requests must be positive; warmup must be non-negative")
	}
	body, err := benchmarkRequestBody(scenario)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency * 2,
		MaxConnsPerHost:     concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
	for index := 0; index < warmup; index++ {
		status, _, err := executeRequest(ctx, client, url, body)
		if err != nil || (scenario == "tail_hit" && status != http.StatusForbidden) {
			return fmt.Errorf("warm-up request failed: status=%d error=%v", status, err)
		}
	}

	durations := make([]time.Duration, requests)
	jobs := make(chan int)
	statusCounts := make(map[int]int64)
	var statusMu sync.Mutex
	var successCount atomic.Int64
	var errorCount atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				status, duration, requestErr := executeRequest(ctx, client, url, body)
				durations[index] = duration
				statusMu.Lock()
				statusCounts[status]++
				statusMu.Unlock()
				if requestErr != nil || (scenario == "tail_hit" && status != http.StatusForbidden) {
					errorCount.Add(1)
					continue
				}
				successCount.Add(1)
			}
		}()
	}
	for index := 0; index < requests; index++ {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	var total time.Duration
	for _, duration := range durations {
		total += duration
	}
	result := loadResult{
		Scenario:       scenario,
		Concurrency:    concurrency,
		Requests:       requests,
		Successes:      successCount.Load(),
		Errors:         errorCount.Load(),
		StatusCounts:   statusCounts,
		ElapsedMS:      milliseconds(elapsed),
		RequestsPerSec: float64(requests) / elapsed.Seconds(),
		AverageLatency: milliseconds(total / time.Duration(requests)),
		P50Latency:     milliseconds(percentile(durations, 0.50)),
		P95Latency:     milliseconds(percentile(durations, 0.95)),
		P99Latency:     milliseconds(percentile(durations, 0.99)),
		MaxLatency:     milliseconds(durations[len(durations)-1]),
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if result.Errors > 0 {
		return fmt.Errorf("load test completed with %d errors", result.Errors)
	}
	return nil
}

func benchmarkRequestBody(scenario string) ([]byte, error) {
	text := strings.Repeat("a", benchmarkTextLength)
	switch scenario {
	case "tail_hit":
		const keyword = "BLOCKED-KEYWORD-00499-Z"
		text = strings.Repeat("a", benchmarkTextLength-len(keyword)-1) + " " + keyword
	case "miss":
	default:
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	return json.Marshal(map[string]any{
		"model":      "risk-bench-model",
		"max_tokens": 1,
		"stream":     false,
		"messages": []map[string]string{
			{"role": "user", "content": text},
		},
	})
}

func executeRequest(ctx context.Context, client *http.Client, url string, body []byte) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+benchmarkAPIKey)
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return 0, duration, err
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return resp.StatusCode, duration, readErr
	}
	return resp.StatusCode, duration, closeErr
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * quantile)
	return values[index]
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
