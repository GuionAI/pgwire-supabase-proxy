package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/pgwire-supabase-proxy/internal/dagger"
)

type PgwireSupabaseProxy struct{}

// Build builds the container image using multi-stage Docker build
func (m *PgwireSupabaseProxy) Build(source *dagger.Directory) *dagger.Container {
	// Builder stage: compile Rust release binary
	builder := dag.Container().
		From("rust:latest").
		WithDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"cargo", "build", "--release"}).
		WithExec([]string{"strip", "target/release/pgwire-supabase-proxy"})

	return dag.Container().
		From("debian:bookworm-slim").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", "ca-certificates"}).
		WithExec([]string{"rm", "-rf", "/var/lib/apt/lists/*"}).
		WithFile("/usr/local/bin/pgwire-supabase-proxy",
			builder.File("/src/target/release/pgwire-supabase-proxy")).
		WithExposedPort(5432).
		WithEntrypoint([]string{"pgwire-supabase-proxy"})
}

// Check runs cargo check and cargo test
func (m *PgwireSupabaseProxy) Check(ctx context.Context, source *dagger.Directory) (string, error) {
	return dag.Container().
		From("rust:latest").
		WithDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"cargo", "check"}).
		WithExec([]string{"cargo", "test"}).
		Stdout(ctx)
}

// publishContainer publishes a container to multiple tags under registry/image.
func publishContainer(ctx context.Context, container *dagger.Container, registry, image, tags string) (string, error) {
	var lastRef string
	for _, tag := range strings.Split(tags, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		ref := fmt.Sprintf("%s/%s:%s", registry, image, tag)
		published, err := container.Publish(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("publish %s: %w", ref, err)
		}
		lastRef = published
	}
	if lastRef == "" {
		return "", fmt.Errorf("no valid tags provided")
	}
	return lastRef, nil
}

// Publish builds and publishes the container image to a registry
func (m *PgwireSupabaseProxy) Publish(
	ctx context.Context,
	source *dagger.Directory,
	registry string,
	image string,
	tags string,
) (string, error) {
	return publishContainer(ctx, m.Build(source), registry, image, tags)
}
