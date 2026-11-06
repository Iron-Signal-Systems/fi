//go:build !freebsd

package recordingest

import "errors"

func cloneDeferredDataFile(src,dst string,expected int64)error{
 return errors.New("deferred clone: requires FreeBSD 15 with ZFS block cloning")
}
