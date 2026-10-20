package versioning

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// chromeReleaseFetcher is the production ReleaseMonitorFetcher: it drives
// headless Chrome to get past release-monitoring.org's Anubis bot
// detection, which a plain HTTP client can't do.
type chromeReleaseFetcher struct {
	browserCtx context.Context
	token      string

	startOnce sync.Once
	startErr  error
}

// NewChromeReleaseFetcher sets up (but does not launch) a shared headless
// Chrome context for the run. Nothing actually starts until the first
// FetchProject call — a run where no package uses a release-monitor never
// pays Chrome's startup cost at all. The caller must invoke cleanup
// regardless of whether the browser ever actually launched.
func NewChromeReleaseFetcher(ctx context.Context, token string) (fetcher ReleaseMonitorFetcher, cleanup func()) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
		chromedp.WindowSize(1920, 1080),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx) // still allocates nothing yet

	cleanup = func() {
		browserCancel()
		allocCancel()
	}
	return &chromeReleaseFetcher{browserCtx: browserCtx, token: token}, cleanup
}

func (f *chromeReleaseFetcher) ensureStarted() error {
	f.startOnce.Do(func() {
		f.startErr = chromedp.Do(f.browserCtx)
	})
	return f.startErr
}

func (f *chromeReleaseFetcher) FetchProject(ctx context.Context, projectID int) (ReleaseProject, error) {
	if err := f.ensureStarted(); err != nil {
		return ReleaseProject{}, fmt.Errorf("starting headless chrome: %w", err)
	}

	log := clog.FromContext(ctx)
	url := fmt.Sprintf(
		"https://release-monitoring.org/api/v2/versions/?project_id=%d",
		projectID,
	)

	tabCtx, cancelTab := chromedp.NewContext(f.browserCtx)
	defer cancelTab()

	tabCtx, cancelTimeout := context.WithTimeout(tabCtx, 90*time.Second)
	defer cancelTimeout()

	headers := map[string]any{
		"Authorization": "Bearer " + f.token,
		"Accept":        "application/json",
	}

	// Run protocol commands using the new typed API.
	if _, err := chromedp.Call(
		tabCtx,
		network.Enable,
		network.EnableParams{},
	); err != nil {
		return ReleaseProject{}, fmt.Errorf("enabling network: %w", err)
	}

	if _, err := chromedp.Call(
		tabCtx,
		network.SetExtraHTTPHeaders,
		network.SetExtraHTTPHeadersParams{
			Headers: network.Headers(headers),
		},
	); err != nil {
		return ReleaseProject{}, fmt.Errorf("setting HTTP headers: %w", err)
	}

	if err := chromedp.Do(tabCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(15*time.Second),
		chromedp.WaitVisible(chromedp.CSS("body")),
	); err != nil {
		return ReleaseProject{}, fmt.Errorf("failed to fetch: %w", err)
	}

	// Evaluate now returns its value rather than filling a pointer.
	jsonBody, err := chromedp.Run(
		tabCtx,
		chromedp.Evaluate[string](`document.body.innerText`),
	)
	if err != nil {
		return ReleaseProject{}, fmt.Errorf("reading response body: %w", err)
	}

	log.Debug("previewing response", "response_preview", truncate(jsonBody, 200))

	if strings.Contains(jsonBody, "Access Denied") ||
		strings.Contains(jsonBody, "Making sure you're not a bot") {
		return ReleaseProject{}, fmt.Errorf(
			"blocked by Anubis: %s",
			truncate(jsonBody, 100),
		)
	}

	var project ReleaseProject
	if err := json.Unmarshal([]byte(jsonBody), &project); err != nil {
		return ReleaseProject{}, fmt.Errorf("failed to decode response body: %w", err)
	}

	return project, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}
