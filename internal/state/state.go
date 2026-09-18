// Package state persists per-package update-check state (last checked
// time, last known version) between runs.
package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/chainguard-dev/clog"
)

// State is what's persisted per package between runs.
type State struct {
	LastVersion string    `json:"last_version"`
	LastChecked time.Time `json:"last_checked"`
}

// Store persists per-package state. Load on a key with no prior state
// returns a zero State and a nil error — that's not a Store failure.
type Store interface {
	Load(ctx context.Context, key string) (State, error)
	Save(ctx context.Context, key string, s State) error
}

// Key builds the storage key for one package's state.
func Key(owner, repo, packageName string) string {
	return fmt.Sprintf("state/%s/%s/%s.json", owner, repo, packageName)
}

// S3Store is the production Store, backed by an S3-compatible bucket.
type S3Store struct {
	Client *s3.Client
	Bucket string
}

func (s S3Store) Load(ctx context.Context, key string) (State, error) {
	resp, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	if err != nil {
		if apiErr, ok := errors.AsType[smithy.APIError](err); ok && apiErr.ErrorCode() == "NoSuchKey" {
			clog.FromContext(ctx).Debug("no existing state found, initializing new state", "key", key)
			return State{}, nil
		}
		return State{}, fmt.Errorf("fetching state from S3: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return State{}, fmt.Errorf("decoding package state: %w", err)
	}
	return st, nil
}

func (s S3Store) Save(ctx context.Context, key string, st State) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encoding package state: %w", err)
	}
	_, err = s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), Body: bytes.NewReader(data)})
	return err
}

// DryRunStore reads through to a real Store but never writes — the same
// live-reads/stubbed-writes convention used by ghrepo and dashboard's
// dry-run implementations.
type DryRunStore struct {
	Store
}

func (s DryRunStore) Save(ctx context.Context, key string, _ State) error {
	clog.FromContext(ctx).Info("DRY RUN: would save package state", "key", key)
	return nil
}
