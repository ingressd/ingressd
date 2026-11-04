// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package apply

import (
	"context"
	"errors"

	"github.com/ingressd/ingressd/internal/render"
)

// Net is only implemented on Linux, where the edge runs.
func Net(context.Context, render.Network) error {
	return errors.New("network configuration requires Linux")
}
