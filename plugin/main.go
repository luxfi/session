// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SessionVM plugin entry point
//
// This is the main binary that runs as a Lux VM plugin.
// It can run standalone or be loaded by luxd.
//
// Build: go build -o sessionvm ./plugin/
// Install: cp sessionvm ~/.lux/plugins/<VMID>

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/luxfi/log"
	"github.com/luxfi/session/vm"
)

func main() {
	logger := log.New("component", "sessionvm-plugin")

	logger.Info("starting SessionVM plugin", "version", "v0.1.0", "vmid", vm.VMID)

	// Create VM factory
	factory := &vm.Factory{}

	// Create VM instance
	vmInstance, err := factory.New(logger)
	if err != nil {
		logger.Error("failed to create VM", "error", err)
		os.Exit(1)
	}

	// Create HTTP handlers
	handlers, err := vmInstance.CreateHandlers(context.Background())
	if err != nil {
		logger.Error("failed to create handlers", "error", err)
		os.Exit(1)
	}

	// Start HTTP server for RPC
	mux := http.NewServeMux()
	for path, handler := range handlers {
		mux.Handle(path, handler)
	}

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health, _ := vmInstance.HealthCheck(r.Context())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","data":%v}`, health)
	})

	addr := os.Getenv("SESSIONVM_ADDR")
	if addr == "" {
		addr = ":9652"
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("shutting down SessionVM...")
		server.Shutdown(context.Background())
	}()

	logger.Info("SessionVM listening", "addr", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("SessionVM stopped")
}
