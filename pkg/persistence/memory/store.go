// Package memory is an in-process Store for dev and unit tests only. Production
// uses the Postgres store.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
)

type store struct {
	mu   sync.RWMutex
	jobs map[string]job.ScanJob
}

func NewStore() persistence.Store {
	return &store{jobs: make(map[string]job.ScanJob)}
}

func (s *store) Create(_ context.Context, scanJob job.ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[scanJob.ID]; ok {
		return nil // Same as the INSERT ... ON CONFLICT DO NOTHING the table takes: never overwrite an existing job
	}
	s.jobs[scanJob.ID] = scanJob
	return nil
}

func (s *store) Get(_ context.Context, scanJobID string) (*job.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[scanJobID]
	if !ok {
		return nil, nil
	}
	// A struct copy still shares Report's backing array, so a caller mutating
	// the returned report would mutate the stored one. Dev-only backend, but a
	// silent aliasing bug is not worth keeping.
	clone := j
	if j.Report != nil {
		clone.Report = append(json.RawMessage(nil), j.Report...)
	}
	return &clone, nil
}

func (s *store) UpdateStatus(_ context.Context, scanJobID string, newStatus job.ScanJobStatus, errorMsg ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[scanJobID]
	if !ok {
		return fmt.Errorf("scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	j.Status = newStatus
	if len(errorMsg) > 0 {
		j.Error = errorMsg[0]
	}
	s.jobs[scanJobID] = j
	return nil
}

func (s *store) Finish(_ context.Context, scanJobID string, report json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[scanJobID]
	if !ok {
		return fmt.Errorf("scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	// Clear Error as well: the Postgres store writes the terminal record in one
	// statement, so leaving a stale error here would make the two backends
	// disagree on what a finished job looks like.
	// Copy the report for the same aliasing reason Get copies it on the way out:
	// the Postgres path serializes, so sharing bytes with the caller would make
	// the two backends diverge.
	j.Report = append(json.RawMessage(nil), report...)
	j.Status = job.Finished
	j.Error = ""
	s.jobs[scanJobID] = j
	return nil
}

func (s *store) FailIfQueued(_ context.Context, scanJobID string, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[scanJobID]
	if !ok {
		return fmt.Errorf("scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	if j.Status != job.Queued {
		return nil
	}
	j.Status = job.Failed
	j.Error = errorMsg
	s.jobs[scanJobID] = j
	return nil
}
