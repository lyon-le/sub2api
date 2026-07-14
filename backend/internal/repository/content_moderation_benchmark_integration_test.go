//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	contentModerationBenchmarkKeywordCount = 500
	contentModerationBenchmarkTextLength   = 12000
)

type contentModerationBenchmarkRepo struct{}

func (contentModerationBenchmarkRepo) CreateLog(context.Context, *service.ContentModerationLog) error {
	return nil
}

func (contentModerationBenchmarkRepo) ListLogs(context.Context, service.ContentModerationLogFilter) ([]service.ContentModerationLog, *pagination.PaginationResult, error) {
	return nil, nil, nil
}

func (contentModerationBenchmarkRepo) CountFlaggedByUserSince(context.Context, int64, time.Time, bool) (int, error) {
	return 0, nil
}

func (contentModerationBenchmarkRepo) CleanupExpiredLogs(context.Context, time.Time, time.Time) (*service.ContentModerationCleanupResult, error) {
	return &service.ContentModerationCleanupResult{}, nil
}

func (contentModerationBenchmarkRepo) UpdateLogEmailSent(context.Context, int64, bool) error {
	return nil
}

type countingSettingRepository struct {
	service.SettingRepository
	reads atomic.Int64
}

var (
	contentModerationBenchmarkServiceOnce sync.Once
	contentModerationBenchmarkService     *service.ContentModerationService
	contentModerationBenchmarkSettings    *countingSettingRepository
	contentModerationBenchmarkSetupErr    error
)

func (r *countingSettingRepository) GetValue(ctx context.Context, key string) (string, error) {
	r.reads.Add(1)
	return r.SettingRepository.GetValue(ctx, key)
}

func (r *countingSettingRepository) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	r.reads.Add(1)
	return r.SettingRepository.GetMultiple(ctx, keys)
}

func benchmarkContentModerationKeywords(count int) []string {
	keywords := make([]string, count)
	for i := range keywords {
		keywords[i] = fmt.Sprintf("blocked-keyword-%05d-z", i)
	}
	return keywords
}

func benchmarkContentModerationInput(tailHit bool) service.ContentModerationCheckInput {
	text := strings.Repeat("a", contentModerationBenchmarkTextLength)
	if tailHit {
		const keyword = "BLOCKED-KEYWORD-00499-Z"
		text = strings.Repeat("a", contentModerationBenchmarkTextLength-len(keyword)-1) + " " + keyword
	}
	body, err := json.Marshal(map[string]any{
		"model": "risk-bench-model",
		"messages": []map[string]string{
			{"role": "user", "content": text},
		},
	})
	if err != nil {
		panic(err)
	}
	return service.ContentModerationCheckInput{
		RequestID: "risk-benchmark",
		UserID:    1,
		APIKeyID:  1,
		Endpoint:  "/v1/chat/completions",
		Provider:  service.PlatformOpenAI,
		Model:     "risk-bench-model",
		Protocol:  service.ContentModerationProtocolOpenAIChat,
		Body:      body,
	}
}

func benchmarkContentModerationService(b *testing.B) (*service.ContentModerationService, *countingSettingRepository) {
	b.Helper()
	contentModerationBenchmarkServiceOnce.Do(func() {
		cfg := service.ContentModerationConfig{
			Enabled:              true,
			Mode:                 service.ContentModerationModePreBlock,
			SampleRate:           100,
			AllGroups:            true,
			RecordNonHits:        false,
			WorkerCount:          4,
			QueueSize:            32768,
			BlockStatus:          403,
			BlockMessage:         "blocked by benchmark",
			EmailOnHit:           false,
			AutoBanEnabled:       false,
			PreHashCheckEnabled:  false,
			BlockedKeywords:      benchmarkContentModerationKeywords(contentModerationBenchmarkKeywordCount),
			KeywordBlockingMode:  service.ContentModerationKeywordModeKeywordOnly,
			ModelFilter:          service.ContentModerationModelFilter{Type: service.ContentModerationModelFilterAll},
			HitRetentionDays:     180,
			NonHitRetentionDays:  3,
			ViolationWindowHours: 720,
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			contentModerationBenchmarkSetupErr = err
			return
		}

		integrationDB.SetMaxOpenConns(50)
		integrationDB.SetMaxIdleConns(10)
		repo := NewSettingRepository(integrationEntClient)
		if err := repo.SetMultiple(context.Background(), map[string]string{
			service.SettingKeyRiskControlEnabled:      "true",
			service.SettingKeyContentModerationConfig: string(raw),
		}); err != nil {
			contentModerationBenchmarkSetupErr = err
			return
		}
		contentModerationBenchmarkSettings = &countingSettingRepository{SettingRepository: repo}
		contentModerationBenchmarkService = service.NewContentModerationService(
			contentModerationBenchmarkSettings,
			contentModerationBenchmarkRepo{},
			nil,
			nil,
			nil,
			nil,
			nil,
		)
	})
	if contentModerationBenchmarkSetupErr != nil {
		b.Fatal(contentModerationBenchmarkSetupErr)
	}
	return contentModerationBenchmarkService, contentModerationBenchmarkSettings
}

func runContentModerationRealDBBenchmark(b *testing.B, tailHit bool) {
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(originalLogger) })

	svc, settings := benchmarkContentModerationService(b)
	input := benchmarkContentModerationInput(tailHit)
	decision, err := svc.Check(context.Background(), input)
	if err != nil {
		b.Fatal(err)
	}
	if tailHit != decision.Blocked {
		b.Fatalf("unexpected warm-up decision: blocked=%v", decision.Blocked)
	}

	settings.reads.Store(0)
	b.ReportAllocs()
	b.ResetTimer()
	var failed atomic.Bool
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := svc.Check(context.Background(), input)
			if err != nil || decision == nil || decision.Blocked != tailHit {
				failed.Store(true)
			}
		}
	})
	b.StopTimer()
	if failed.Load() {
		b.Fatal("content moderation benchmark returned an unexpected result")
	}
	if b.N > 0 {
		b.ReportMetric(float64(settings.reads.Load())/float64(b.N), "setting_reads/op")
	}
}

func BenchmarkContentModerationKeywordMissRealDB(b *testing.B) {
	runContentModerationRealDBBenchmark(b, false)
}

func BenchmarkContentModerationKeywordTailHitRealDB(b *testing.B) {
	runContentModerationRealDBBenchmark(b, true)
}
