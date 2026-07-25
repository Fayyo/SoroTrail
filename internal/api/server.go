// Package api serves stored events over HTTP. Endpoints are documented in
// the README's API reference.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/khaylebfortune/sorotrail/internal/audit"
	"github.com/khaylebfortune/sorotrail/internal/broadcast"
	"github.com/khaylebfortune/sorotrail/internal/rpc"
	"github.com/khaylebfortune/sorotrail/internal/store"
)

// SetAuditor registers the binary's Auditor so /stats can surface its
// Metrics counters. There is exactly one Auditor per process; its
// lifetime is the lifetime of main(). SetAuditor must be called BEFORE
// ListenAndServe so the first /stats request observes a stable value.
// The setter is guarded by a RWMutex so concurrent reader goroutines in
// /stats handlers can never observe a torn pointer.
//
// When AUDIT_ENABLED=false the function is never called and /stats
// returns Stats with the embedded AuditStats struct zero-valued (and
// omitted from JSON, courtesy of its `omitempty` tag).
var (
	auditorMu sync.RWMutex
	auditor   *audit.Auditor
)

func SetAuditor(a *audit.Auditor) {
	auditorMu.Lock()
	auditor = a
	auditorMu.Unlock()
}

func getAuditor() *audit.Auditor {
	auditorMu.RLock()
	defer auditorMu.RUnlock()
	return auditor
}

// Enricher is the spec-based event enrichment interface used by the API.
// Defined here so the API package doesn't import internal/spec directly.
type Enricher interface {
	EnrichEvents(ctx context.Context, events []store.Event) []store.EnrichedEvent
}

// Server holds the API's dependencies.
type Server struct {
	store    store.Store
	rpc      rpc.Client
	enricher Enricher
	log      *slog.Logger
	apiKey   string
	limiter  *RateLimiter
	bcast    *broadcast.Broadcaster

	// cachedLatestLedger caches the latest ledger from RPC health check
	// to avoid hammering the RPC on every /stats request.
	cachedLatestLedger struct {
		mu        sync.RWMutex
		ledger    int64
		expiresAt time.Time
	}
}

// New builds the API server. rpcClient is only used by /health.
// apiKey gates the watched-contracts management endpoints; pass "" to
// fail closed (every request gets a 503 with "API_KEY not configured").
// See apiKeyAuth for the exact contract. The trailing enricher is optional —
// pass nil to disable spec decoding, or one Enricher to enable it.
func New(st store.Store, rpcClient rpc.Client, log *slog.Logger, apiKey string, enricher ...Enricher) *Server {
	s := &Server{store: st, rpc: rpcClient, log: log, apiKey: apiKey}
	if len(enricher) > 0 {
		s.enricher = enricher[0]
	}
	return s
}

// SetRateLimiter wires a per-client rate limiter into the router. Pass
// nil to leave the limiter disabled (the default — no behavior change).
// The limiter's Start/Stop lifecycle is owned by main, not by the Server.
func (s *Server) SetRateLimiter(l *RateLimiter) {
	s.limiter = l
}

// WithBroadcaster attaches the live event broadcaster so streaming endpoints
// (SSE, WebSocket) can deliver events as they arrive.
func (s *Server) WithBroadcaster(b *broadcast.Broadcaster) *Server {
	s.bcast = b
	return s
}

// Router returns the HTTP handler with all routes mounted.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	if s.limiter != nil {
		// Limiter sits inside Timeout and Recoverer so its instant 429
		// response always makes it back through the deadline cleanly, and
		// a panic inside the limiter can't take down the server.
		r.Use(s.limiter.Middleware)
	}

	r.Get("/health", s.handleHealth)
	r.Get("/events", s.handleListEvents)
	r.Get("/events/{id}", s.handleGetEvent)
	r.Get("/contracts/{id}/events", s.handleContractEvents)
	r.Get("/stats", s.handleStats)
	r.Get("/metrics", s.handleMetrics)
	r.Get("/events/ws", s.handleEventStreamWS)

	// Watched-contracts management: writes and updates to the runtime
	// filter list. Always auth-gated, even when AUTH_ENABLED would be
	// false elsewhere — that asymmetry is intentional and part of the
	// "writes are never open" contract. GET is gated too so an operator
	// with the key can confirm the current list without touching /stats.
	// Routes are absolute (no sub-router) so callers don't need a
	// trailing slash or chi's RedirectSlashes middleware.
	watchedMW := apiKeyAuth(s.apiKey)
	r.With(watchedMW).Get("/watched-contracts", s.handleListWatchedChains)
	r.With(watchedMW).Post("/watched-contracts", s.handleAddWatchedChain)
	r.With(watchedMW).Delete("/watched-contracts/{id}", s.handleRemoveWatchedChain)

	// Subscription CRUD and delivery history.
	r.Post("/subscriptions", s.handleCreateSubscription)
	r.Get("/subscriptions", s.handleListSubscriptions)
	r.Get("/subscriptions/{id}", s.handleGetSubscription)
	r.Put("/subscriptions/{id}", s.handleUpdateSubscription)
	r.Delete("/subscriptions/{id}", s.handleDeleteSubscription)
	r.Get("/subscriptions/{id}/deliveries", s.handleListDeliveries)

	return r
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		s.log.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

// getCachedLatestLedger returns the cached latest ledger from RPC health check,
// fetching a fresh value if the cache has expired (TTL: 5 seconds).
func (s *Server) getCachedLatestLedger(ctx context.Context) (int64, error) {
	s.cachedLatestLedger.mu.RLock()
	if time.Now().Before(s.cachedLatestLedger.expiresAt) && s.cachedLatestLedger.ledger > 0 {
		ledger := s.cachedLatestLedger.ledger
		s.cachedLatestLedger.mu.RUnlock()
		return ledger, nil
	}
	s.cachedLatestLedger.mu.RUnlock()

	// Cache miss or expired - fetch fresh value
	s.cachedLatestLedger.mu.Lock()
	defer s.cachedLatestLedger.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(s.cachedLatestLedger.expiresAt) && s.cachedLatestLedger.ledger > 0 {
		return s.cachedLatestLedger.ledger, nil
	}

	if s.rpc == nil {
		return 0, nil
	}

	health, err := s.rpc.GetHealth(ctx)
	if err != nil {
		// Return stale value if available, otherwise error
		if s.cachedLatestLedger.ledger > 0 {
			return s.cachedLatestLedger.ledger, nil
		}
		return 0, err
	}

	ledger := int64(health.LatestLedger)
	s.cachedLatestLedger.ledger = ledger
	s.cachedLatestLedger.expiresAt = time.Now().Add(5 * time.Second)
	return ledger, nil
}

// handleMetrics exposes Prometheus metrics including ingestion lag.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		s.log.Error("loading stats for metrics", "error", err)
		http.Error(w, "loading stats failed", http.StatusInternalServerError)
		return
	}

	// Get latest ledger from cache/RPC to compute lag
	head, err := s.getCachedLatestLedger(r.Context())
	if err != nil {
		s.log.Warn("loading latest ledger for metrics", "error", err)
		// Still emit stats without lag if we have last ingested
		if stats.LastIngestedLedger > 0 {
			head = stats.LastIngestedLedger // lag will be 0
		} else {
			http.Error(w, "loading latest ledger failed", http.StatusInternalServerError)
			return
		}
	}

	lag := ingestLagLedgers(head, stats.LastIngestedLedger)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP sorotrail_ingest_lag_ledgers Ingestion lag in ledgers (chain_head - last_ingested)\n")
	fmt.Fprintf(w, "# TYPE sorotrail_ingest_lag_ledgers gauge\n")
	fmt.Fprintf(w, "sorotrail_ingest_lag_ledgers %d\n", lag)
	fmt.Fprintf(w, "# HELP sorotrail_last_ingested_ledger Last ingested ledger sequence\n")
	fmt.Fprintf(w, "# TYPE sorotrail_last_ingested_ledger gauge\n")
	fmt.Fprintf(w, "sorotrail_last_ingested_ledger %d\n", stats.LastIngestedLedger)
	fmt.Fprintf(w, "# HELP sorotrail_chain_head_ledger Latest ledger from RPC\n")
	fmt.Fprintf(w, "# TYPE sorotrail_chain_head_ledger gauge\n")
	fmt.Fprintf(w, "sorotrail_chain_head_ledger %d\n", head)
	fmt.Fprintf(w, "# HELP sorotrail_total_events Total number of events stored\n")
	fmt.Fprintf(w, "# TYPE sorotrail_total_events gauge\n")
	fmt.Fprintf(w, "sorotrail_total_events %d\n", stats.TotalEvents)
	fmt.Fprintf(w, "# HELP sorotrail_contract_count Number of unique contracts with events\n")
	fmt.Fprintf(w, "# TYPE sorotrail_contract_count gauge\n")
	fmt.Fprintf(w, "sorotrail_contract_count %d\n", stats.ContractCount)
	fmt.Fprintf(w, "# HELP sorotrail_watched_contracts Number of watched contracts\n")
	fmt.Fprintf(w, "# TYPE sorotrail_watched_contracts gauge\n")
	fmt.Fprintf(w, "sorotrail_watched_contracts %d\n", stats.WatchedContracts)
}
