package ghrepo

import (
	"context"
	"errors"
	"fmt"
)

// BotLogin implements app.IdentityResolver: it reports the GitHub login
// melange-renovator is currently authenticated as.
func BotLogin(ctx context.Context, gh GitHubAPI) (string, error) {
	reqBody := struct {
		Query string `json:"query"`
	}{Query: `query { viewer { login } }`}

	req, err := gh.NewRequest("POST", "graphql", reqBody)
	if err != nil {
		return "", fmt.Errorf("building viewer identity query: %w", err)
	}

	var result struct {
		Data struct {
			Viewer struct {
				Login string `json:"login"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if _, err := gh.Do(ctx, req, &result); err != nil {
		return "", fmt.Errorf("querying authenticated identity: %w", err)
	}

	login := result.Data.Viewer.Login
	if login == "" {
		return "", errors.New("viewer query returned an empty login")
	}
	return login, nil
}
