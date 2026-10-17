// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	AdminSocketDirectory = "/var/db/fi-keeper/admin"
	AdminSocketName      = "admin.sock"
	adminRequestTimeout  = 10 * time.Second
)

type AdminSocketAuthority struct {
	Directory string
	KeeperUID uint32
	KeeperGID uint32
}

// VerifyAdminSocketAuthority requires a keeper-owned, private parent and
// directory. No worker-accessible Unix socket or pathname is acceptable.
func VerifyAdminSocketAuthority(policy AdminSocketAuthority, bound bool) error {
	if policy.KeeperUID == 0 || policy.Directory == "" ||
		!filepath.IsAbs(policy.Directory) ||
		filepath.Clean(policy.Directory) != policy.Directory ||
		len(filepath.Join(policy.Directory, AdminSocketName)) >= 104 {
		return errors.New("invalid keeper administrative socket authority")
	}
	resolved, err := filepath.EvalSymlinks(policy.Directory)
	if err != nil {
		return err
	}
	if resolved != policy.Directory {
		return errors.New("admin socket directory traverses a symlink")
	}
	parentFD, err := unix.Open(filepath.Dir(policy.Directory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&07777 != 0700 ||
		parent.Uid != policy.KeeperUID || parent.Gid != policy.KeeperGID {
		return errors.New("admin socket parent must be private keeper-owned directory")
	}
	dirFD, err := unix.Openat(parentFD, filepath.Base(policy.Directory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	var directory unix.Stat_t
	if err := unix.Fstat(dirFD, &directory); err != nil {
		return err
	}
	if directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&07777 != 0700 ||
		directory.Uid != policy.KeeperUID || directory.Gid != policy.KeeperGID {
		return errors.New("admin socket directory must be private keeper-owned directory")
	}
	var endpoint unix.Stat_t
	err = unix.Fstatat(dirFD, AdminSocketName, &endpoint, unix.AT_SYMLINK_NOFOLLOW)
	if !bound {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("administrative socket pathname already occupied")
	}
	if err != nil {
		return err
	}
	if endpoint.Mode&unix.S_IFMT != unix.S_IFSOCK || endpoint.Mode&07777 != 0600 ||
		endpoint.Uid != policy.KeeperUID || endpoint.Gid != policy.KeeperGID {
		return errors.New("administrative socket ownership or mode mismatch")
	}
	return nil
}

// BindAdminSocket leaves the endpoint on close; stale socket retirement must
// be an explicit, verified lifecycle action. It does not create directories.
func BindAdminSocket(policy AdminSocketAuthority) (*net.UnixListener, error) {
	if uint32(os.Geteuid()) != policy.KeeperUID || uint32(os.Getegid()) != policy.KeeperGID {
		return nil, errors.New("administrative socket binding requires keeper identity")
	}
	if err := VerifyAdminSocketAuthority(policy, false); err != nil {
		return nil, err
	}
	path := filepath.Join(policy.Directory, AdminSocketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := VerifyAdminSocketAuthority(policy, true); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// VerifyRootAdminPeer reads FreeBSD kernel credentials rather than trusting
// any UID, operator name, or authorization claim in the request body.
func VerifyRootAdminPeer(conn *net.UnixConn) error {
	if conn == nil {
		return errors.New("missing administrative connection")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred == nil || cred.Version != keeperXucredVersion ||
		cred.Ngroups < 1 || int(cred.Ngroups) > len(cred.Groups) || cred.Uid != 0 {
		return errors.New("administrative release requires kernel-verified root peer")
	}
	return nil
}

type AdminReleaseHandler func(context.Context, KeeperReleaseRequest) (string, error)

// HandleAdminReleaseConnection authenticates the root peer BEFORE parsing
// or forwarding a release request. It must only be supplied a handler that
// acquires the keeper-side protected singleton lock before releasing state.
// M6A deliberately does not provide or wire any such handler.
func HandleAdminReleaseConnection(conn *net.UnixConn, handler AdminReleaseHandler) error {
	if conn == nil {
		return errors.New("missing administrative connection")
	}
	defer conn.Close()
	if handler == nil {
		return errors.New("administrative release is not enabled")
	}
	deadline := time.Now().Add(adminRequestTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := VerifyRootAdminPeer(conn); err != nil {
		return err
	}
	wire, err := ReadAdminReleaseRequest(conn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	path, err := handler(ctx, KeeperReleaseRequest{
		SourceID: wire.SourceID, ConfirmSource: wire.ConfirmSource,
		Reference: wire.Reference, Justification: wire.Justification, OperatorUID: 0,
	})
	if err != nil {
		// Do not return internal filesystem errors over the socket.
		_ = WriteAdminReleaseResponse(conn, AdminReleaseResponse{
			Version: AdminProtocolVersion, Status: "error", ErrorCode: "RELEASE_REJECTED",
		})
		return fmt.Errorf("keeper administrative release rejected: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return WriteAdminReleaseResponse(conn, AdminReleaseResponse{
		Version: AdminProtocolVersion, Status: "released", AuditPath: path,
	})
}
