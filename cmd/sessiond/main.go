// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// sessiond is the Lux session layer daemon.
// It runs as a service node for private permissionless workloads.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/luxfi/session/daemon"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	// Parse flags
	var (
		listenAddr     = flag.String("listen", ":9651", "Listen address")
		dataDir        = flag.String("data-dir", "", "Data directory")
		maxSessions    = flag.Int("max-sessions", 100, "Maximum concurrent sessions")
		showVersion    = flag.Bool("version", false, "Show version")
		bootstrapPeers = flag.String("bootstrap", "", "Comma-separated bootstrap peers")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("sessiond version %s (commit %s)\n", version, commit)
		os.Exit(0)
	}

	// Create config
	config := daemon.DefaultConfig()
	config.ListenAddr = *listenAddr
	config.DataDir = *dataDir
	config.MaxSessions = *maxSessions

	if *bootstrapPeers != "" {
		// Parse bootstrap peers
		// config.BootstrapPeers = strings.Split(*bootstrapPeers, ",")
		_ = bootstrapPeers
	}

	// Create service
	service := daemon.New(config)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start service
	if err := service.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start service: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("sessiond started on %s\n", config.ListenAddr)

	// Wait for shutdown signal
	<-sigCh
	fmt.Println("\nShutting down...")

	// Stop service
	if err := service.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "error during shutdown: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Shutdown complete")
}
