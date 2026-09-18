package dashboard

// Actions captures the manual actions a user requested via
// checkboxes in the dependency dashboard issue since the tool last ran.
type Actions struct {
	RebasePR     map[string]bool
	RebaseAll    bool
	RecreatePR   map[string]bool
	RecreateAll  bool
	RetryPackage map[string]bool
	RetryAll     bool
}
