package executor

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

// resetQwenRateLimiter clears all rate limiter state for clean tests.
func resetQwenRateLimiter() {
	qwenRateLimiter.Lock()
	qwenRateLimiter.requests = make(map[string][]time.Time)
	qwenRateLimiter.Unlock()
}

func TestWaitForQwenRateLimit_AllowsRequestsUnderLimit(t *testing.T) {
	resetQwenRateLimiter()
	ctx := context.Background()

	// Should allow 59 requests without blocking
	for i := 0; i < 59; i++ {
		if err := waitForQwenRateLimit(ctx, "test-auth-1"); err != nil {
			t.Fatalf("request %d should succeed, got error: %v", i, err)
		}
	}
}

func TestWaitForQwenRateLimit_EmptyAuthIDSkips(t *testing.T) {
	resetQwenRateLimiter()
	ctx := context.Background()

	err := waitForQwenRateLimit(ctx, "")
	if err != nil {
		t.Fatalf("empty authID should skip rate limit, got error: %v", err)
	}
}

func TestWaitForQwenRateLimit_BlocksAndRecoversThenAllows(t *testing.T) {
	resetQwenRateLimiter()
	ctx := context.Background()
	authID := "test-auth-block"

	// Fill up the rate limiter window with timestamps spread across the past minute
	qwenRateLimiter.Lock()
	timestamps := make([]time.Time, qwenRateLimitPerMin)
	// Put all 60 requests 55 seconds ago so they expire in ~5 seconds
	expireAt := time.Now().Add(-55 * time.Second)
	for i := 0; i < qwenRateLimitPerMin; i++ {
		timestamps[i] = expireAt
	}
	qwenRateLimiter.requests[authID] = timestamps
	qwenRateLimiter.Unlock()

	// The next request should block but eventually succeed (within ~6 seconds)
	start := time.Now()
	err := waitForQwenRateLimit(ctx, authID)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected request to succeed after waiting, got error: %v", err)
	}
	// Should have waited at least 4 seconds (55s ago + 60s window = 5s wait)
	if elapsed < 4*time.Second {
		t.Errorf("expected to wait at least 4s, but waited %v", elapsed)
	}
	if elapsed > 15*time.Second {
		t.Errorf("waited too long: %v (expected ~5s)", elapsed)
	}
}

func TestWaitForQwenRateLimit_RespectsContextCancellation(t *testing.T) {
	resetQwenRateLimiter()
	authID := "test-auth-cancel"

	// Fill up the rate limiter to force blocking
	qwenRateLimiter.Lock()
	timestamps := make([]time.Time, qwenRateLimitPerMin)
	now := time.Now()
	for i := 0; i < qwenRateLimitPerMin; i++ {
		timestamps[i] = now // All 60 requests "just now" = will block for ~60s
	}
	qwenRateLimiter.requests[authID] = timestamps
	qwenRateLimiter.Unlock()

	// Create context that cancels after 500ms
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := waitForQwenRateLimit(ctx, authID)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("context cancellation took too long: %v", elapsed)
	}
}

func TestWaitForQwenRateLimit_ConcurrentRequestsSafe(t *testing.T) {
	resetQwenRateLimiter()
	ctx := context.Background()
	authID := "test-auth-concurrent"

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	// Launch 20 concurrent requests
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := waitForQwenRateLimit(ctx, authID); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent request failed: %v", err)
	}
}

func TestIsQwenDailyQuotaError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "insufficient_quota code",
			body: `{"error":{"code":"insufficient_quota","message":"You have exceeded your daily quota"}}`,
			want: true,
		},
		{
			name: "insufficient_quota in message",
			body: `{"error":{"code":"unknown","message":"insufficient_quota error occurred"}}`,
			want: true,
		},
		{
			name: "free allocated quota exceeded - NOT daily",
			body: `{"error":{"code":"quota_exceeded","message":"Free allocated quota exceeded."}}`,
			want: false,
		},
		{
			name: "rate limit error - NOT daily",
			body: `{"error":{"code":"rate_limit_exceeded","message":"Too many requests"}}`,
			want: false,
		},
		{
			name: "empty body",
			body: `{}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isQwenDailyQuotaError([]byte(tt.body))
			if got != tt.want {
				t.Errorf("isQwenDailyQuotaError(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestIsQwenRateLimitError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "free allocated quota exceeded",
			body: `{"error":{"code":"rate_limit","message":"Free allocated quota exceeded."}}`,
			want: true,
		},
		{
			name: "quota_exceeded code",
			body: `{"error":{"code":"quota_exceeded","message":"You have exceeded your limit"}}`,
			want: true,
		},
		{
			name: "too many requests in message",
			body: `{"error":{"code":"unknown","message":"Too many requests, please retry"}}`,
			want: true,
		},
		{
			name: "rate limit in message",
			body: `{"error":{"code":"unknown","message":"Rate limit exceeded"}}`,
			want: true,
		},
		{
			name: "daily quota - NOT rate limit",
			body: `{"error":{"code":"insufficient_quota","message":"Daily quota exhausted"}}`,
			want: false,
		},
		{
			name: "empty body",
			body: `{}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isQwenRateLimitError([]byte(tt.body))
			if got != tt.want {
				t.Errorf("isQwenRateLimitError(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestWrapQwenError_PerMinuteRateLimit(t *testing.T) {
	ctx := context.Background()

	// "Free allocated quota exceeded" with HTTP 429 should get SHORT retry
	body := []byte(`{"error":{"code":"quota_exceeded","message":"Free allocated quota exceeded."}}`)
	errCode, retryAfter := wrapQwenError(ctx, http.StatusTooManyRequests, body)

	if errCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", errCode)
	}
	if retryAfter == nil {
		t.Fatal("expected retryAfter to be set")
	}
	// Should be ~65 seconds, NOT hours until tomorrow
	if *retryAfter > 2*time.Minute {
		t.Errorf("retryAfter too long for per-minute rate limit: %v (should be ~65s)", *retryAfter)
	}
	if *retryAfter < 30*time.Second {
		t.Errorf("retryAfter too short: %v (should be ~65s)", *retryAfter)
	}
}

func TestWrapQwenError_DailyQuotaExhaustion(t *testing.T) {
	ctx := context.Background()

	// "insufficient_quota" with HTTP 403 should get LONG retry (until tomorrow)
	body := []byte(`{"error":{"code":"insufficient_quota","message":"Your daily quota is exhausted"}}`)
	errCode, retryAfter := wrapQwenError(ctx, http.StatusForbidden, body)

	if errCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 (mapped), got %d", errCode)
	}
	if retryAfter == nil {
		t.Fatal("expected retryAfter to be set")
	}
	// Should be hours until tomorrow, not 65 seconds
	if *retryAfter < time.Hour {
		t.Errorf("retryAfter too short for daily quota: %v (should be hours)", *retryAfter)
	}
}

func TestWrapQwenError_NonQuotaError(t *testing.T) {
	ctx := context.Background()

	// A regular 500 error should pass through unchanged
	body := []byte(`{"error":{"code":"server_error","message":"Internal server error"}}`)
	errCode, retryAfter := wrapQwenError(ctx, http.StatusInternalServerError, body)

	if errCode != http.StatusInternalServerError {
		t.Errorf("expected 500 unchanged, got %d", errCode)
	}
	if retryAfter != nil {
		t.Errorf("expected no retryAfter for 500 error, got %v", *retryAfter)
	}
}

func TestWrapQwenError_Unknown429(t *testing.T) {
	ctx := context.Background()

	// Unknown 429 with no recognizable error body should get short retry
	body := []byte(`{"error":{"code":"unknown","message":"Something went wrong"}}`)
	errCode, retryAfter := wrapQwenError(ctx, http.StatusTooManyRequests, body)

	if errCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", errCode)
	}
	if retryAfter == nil {
		t.Fatal("expected retryAfter for unknown 429")
	}
	// Should be short retry (~65s)
	if *retryAfter > 2*time.Minute {
		t.Errorf("retryAfter too long for unknown 429: %v", *retryAfter)
	}
}
