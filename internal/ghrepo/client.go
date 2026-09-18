package ghrepo

import "context"

// Reader is the read-only slice of the GitHub API PR reconciliation needs.
// It is always backed by the real API, in both live and dry-run mode —
// dry-run only stops writes, never observation of real repository state.
type Reader interface {
	DefaultBranch(ctx context.Context) (string, error)
	BranchExists(ctx context.Context, branch string) (bool, error)
	FindOpenPR(ctx context.Context, branch string) (*PullRequest, error)
	FindClosedPR(ctx context.Context, branch string) (*PullRequest, error)
	ListOpenPRsWithTitlePrefix(ctx context.Context, prefix string) ([]*PullRequest, error)
	FileContent(ctx context.Context, path, ref string) (string, error)
	BranchTipSHA(ctx context.Context, branch string) (string, error)
	CompareCommits(ctx context.Context, base, head string) (*Comparison, error)
	RequiresUpToDateBranch(ctx context.Context, branch string) (bool, error)
}

// Writer is every mutating GitHub operation PR reconciliation needs. The
// dry-run implementation logs instead of calling the API; the live
// implementation is a thin, retrying wrapper around go-github.
type Writer interface {
	CommitFile(ctx context.Context, branch, parentSHA string, branchExists bool, path string, content []byte, message string) (sha string, err error)
	CreatePullRequest(ctx context.Context, head, base, title, body string) (*PullRequest, error)
	ClosePullRequest(ctx context.Context, number int) error
	ReopenPullRequest(ctx context.Context, number int) error
	SetPullRequestBody(ctx context.Context, number int, body string) error
	RetargetPullRequestBase(ctx context.Context, number int, base string) error
	AddLabels(ctx context.Context, number int, labels []string) error
	CreateIssueComment(ctx context.Context, number int, body string) error
	DeleteRef(ctx context.Context, ref string) error
}

// Client is everything Reconciler needs from GitHub for one repository.
type Client interface {
	Reader
	Writer
}

// NewClient builds the Client for one repository. In dry-run mode, reads
// still hit the real API — only Writer methods are stubbed and logged.
func NewClient(gh GitHubAPI, owner, repo string, dryRun bool) Client {
	live := &liveClient{gh: gh, owner: owner, repo: repo}
	if dryRun {
		return &dryRunClient{Reader: live, owner: owner, repo: repo}
	}
	return live
}
