package renovator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/chainguard-dev/clog"
)

func loadPackageState(ctx context.Context, client *s3.Client, bucket, key string) (packageState, error) {
	log := clog.FromContext(ctx)

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
			if apiErr.ErrorCode() == "NoSuchKey" {
				log.Debug("no existing state found in S3, initializing new state", "key", key)
				return packageState{}, nil
			}
		}
		return packageState{}, fmt.Errorf("fetching state from S3: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var ps packageState
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return packageState{}, fmt.Errorf("decoding package state: %w", err)
	}

	return ps, nil
}

func savePackageState(ctx context.Context, client *s3.Client, bucket, key string, ps packageState) error {
	data, _ := json.Marshal(ps)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}
