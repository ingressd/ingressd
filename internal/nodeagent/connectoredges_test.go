// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func TestConnectorEdges(t *testing.T) {
	if connectorEdges(nil) != nil {
		t.Error("no report must leave connector_edges out")
	}
	got := connectorEdges([]proto.EdgeReport{
		{Node: "nod_a", EdgePublicKey: "ka", RTTMillis: 12.5, Up: true, Transport: "udp"},
		{Node: "nod_b", EdgePublicKey: "kb"},
	})
	want := []nodeproto.ConnectorEdge{
		{Node: "nod_a", EdgePublicKey: "ka", RTTMillis: 12.5, Up: true, Transport: "udp"},
		{Node: "nod_b", EdgePublicKey: "kb"},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %+v", got)
	}
}
