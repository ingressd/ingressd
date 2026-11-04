// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"errors"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func TestStorageRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := h.ctx()
	req := nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: "certificates/acme/a.example/a.example.crt", Value: []byte("CERT")}
	// hello reaches the panel just before the agent records its session.
	var res nodeproto.StorageResponse
	var err error
	for i := 0; i < 50; i++ {
		if res, err = h.agent.Storage(ctx, req); !errors.Is(err, ErrPanelOffline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || res.Error != "" {
		t.Fatalf("store: %+v, %v", res, err)
	}
	res, err = h.agent.Storage(ctx, nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/acme/a.example/a.example.crt"})
	if err != nil || string(res.Value) != "CERT" {
		t.Fatalf("load: %+v, %v", res, err)
	}
	res, err = h.agent.Storage(ctx, nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/none"})
	if err != nil || !res.NotExist {
		t.Fatalf("load missing: %+v, %v", res, err)
	}
	res, err = h.agent.Storage(ctx, nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "issue_cert_a.example", Owner: "o1"})
	if err != nil || !res.Acquired {
		t.Fatalf("lock: %+v, %v", res, err)
	}
	if keys := h.panel.Storage().Keys(); len(keys) != 1 {
		t.Fatalf("panel keys = %v", keys)
	}
	h.stop()
	if _, err := h.agent.Storage(ctx, req); !errors.Is(err, ErrPanelOffline) {
		t.Fatalf("offline: %v, want ErrPanelOffline", err)
	}
}
