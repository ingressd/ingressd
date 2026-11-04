// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync"

	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

var (
	pipelinesMu sync.Mutex
	pipelines   = map[*env]*pipeline.Pipeline{}
)

// pipeline returns the process-wide apply pipeline for e, so the CLI, the
// serve loop and the admin API serialize their config and secrets writes.
func (e *env) pipeline() *pipeline.Pipeline {
	pipelinesMu.Lock()
	defer pipelinesMu.Unlock()
	if p, ok := pipelines[e]; ok {
		return p
	}
	p := &pipeline.Pipeline{
		ConfigPath:  e.configPath(),
		SecretsPath: e.secretsPath(),
		KeyPath:     e.keyPath,
		Repo:        e.repo(),
		Render:      e.renderOptions(),
		Engine:      e.engine,
		Prepare:     e.prepareApply,
		Keys:        func(cfg *config.Config, st *secrets.Store) render.Keys { return e.tunnelKeys(cfg, st) },
		ExtraPaths:  []string{pki.InventoryFile},
	}
	pipelines[e] = p
	return p
}
