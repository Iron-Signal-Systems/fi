//go:build !windows

package ntfs

import "context"

func CollectPath(context.Context, string, string, string) (Observation, error) {
	return Observation{}, ErrUnsupportedPlatform
}
