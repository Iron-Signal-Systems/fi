// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Test-only PostgreSQL host bridge. The host is not allowed to connect
// directly to PostgreSQL AF_UNIX sockets created in the fi-dev jail. This
// bridge creates short, private, HOST-owned sockets and transports each
// connection over jexec to the original UNIX socket INSIDE fi-dev.
// No TCP listener, DB restart, credential injection or schema modification.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	jailName = "fi-dev"
	profilePrefix = "pg-"
)
var profiles = []string{"W32", "W64", "W96", "W128"}

func validClusterRoot(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p &&
		strings.HasPrefix(p, "/home/jwood/fi-window-bench-") &&
		!strings.Contains(p, "..") && !strings.ContainsAny(p, " *?[]\n\r")
}

func dialInJail(path string) error {
	if !strings.HasPrefix(path, "/home/jwood/fi-window-bench-") ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!strings.Contains(path, "/socket/.s.PGSQL.") {
		return errors.New("FI PG relay: unapproved jail socket path")
	}
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil { return fmt.Errorf("FI PG relay jail dial: %w", err) }
	defer c.Close()
	go func() {
		_, _ = io.Copy(c, os.Stdin)
		if u, ok := c.(*net.UnixConn); ok { _ = u.CloseWrite() }
	}()
	_, err = io.Copy(os.Stdout, c)
	if err != nil { return fmt.Errorf("FI PG relay jail stream: %w", err) }
	return nil
}

func bridgeConnection(client net.Conn, jailBinary, jailSocket string) {
	defer client.Close()
	// Each backend connection gets its own jailed child. The jailed child
	// alone connects to PostgreSQL. The process receives no SQL credentials
	// and does not bypass the original socket's OS permissions.
	cmd := exec.Command("jexec", "-U", "jwood", jailName,
		jailBinary, "-dial", jailSocket)
	cmd.Stdin = client
	cmd.Stdout = client
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "FI PG RELAY child terminated: %v\n", err)
	}
}

func probe(socket string) error {
	c, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil { return err }
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(10*time.Second)); err != nil {return err}
	// PostgreSQL wire SSLRequest is read-only and returns S or N. This
	// proves the entire host->jexec->jail->PostgreSQL round trip, rather
	// than trusting inode visibility or netcat's exit code.
	_, err = c.Write([]byte{0,0,0,8,4,210,22,47})
	if err != nil { return err }
	var reply [1]byte
	_, err = io.ReadFull(c, reply[:])
	if err != nil { return err }
	if reply[0] != 'N' && reply[0] != 'S' {
		return fmt.Errorf("unexpected PostgreSQL SSLRequest reply %#x",reply[0])
	}
	return nil
}

func serve(clusterRoot, outputRoot, jailBinary string, basePort int) error {
	if !validClusterRoot(clusterRoot) {
		return errors.New("FI PG relay: unexpected isolated cluster root")
	}
	if !filepath.IsAbs(outputRoot) || filepath.Clean(outputRoot) != outputRoot ||
		!strings.HasPrefix(outputRoot,"/var/tmp/fi-window-chunks-") {
		return errors.New("FI PG relay: unsafe output root")
	}
	if !filepath.IsAbs(jailBinary) ||
		!strings.HasPrefix(jailBinary,"/home/jwood/fi-w128-chunk-build/") {
		return errors.New("FI PG relay: unexpected jailed executable")
	}
	if basePort != 55531 && basePort != 55631 && basePort != 55731 {
		return errors.New("FI PG relay: unexpected disposable cluster port family")
	}
	if os.Geteuid() != 0 {return errors.New("FI PG relay must run as host root")}
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {_ = l.Close()}
	}()
	limit := make(chan struct{},32)
	var wg sync.WaitGroup
	for i,name := range profiles {
		port := basePort+i
		dir := filepath.Join(outputRoot,profilePrefix+name)
		if err:=os.Mkdir(dir,0700); err != nil {
			return fmt.Errorf("FI PG relay mkdir %s: %w",name,err)
		}
		path := filepath.Join(dir,fmt.Sprintf(".s.PGSQL.%d",port))
		if len(path)>=104 {
			return fmt.Errorf("FI PG relay: host socket path too long (%d)",len(path))
		}
		// Listen directly on the host, not via a symbolic link to the
		// jail's socket. All parent directories must remain mode 0700.
		ln,err:=net.Listen("unix",path)
		if err!=nil {return fmt.Errorf("FI PG relay listen %s: %w",name,err)}
		if err:=os.Chmod(path,0600);err!=nil {_=ln.Close();return err}
		listeners=append(listeners,ln)
		target:=filepath.Join(clusterRoot,name,"socket",fmt.Sprintf(".s.PGSQL.%d",port))
		wg.Add(1)
		go func(l net.Listener,target string) {
			defer wg.Done()
			for {
				c,err:=l.Accept()
				if err!=nil {return}
				select {
				case limit<-struct{}{}:
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func(){<-limit}()
						bridgeConnection(c,jailBinary,target)
					}()
				default:
					_ = c.Close()
				}
			}
		}(ln,target)
	}
	for i,name:=range profiles {
		path:=filepath.Join(outputRoot,profilePrefix+name,
			fmt.Sprintf(".s.PGSQL.%d",basePort+i))
		if err:=probe(path);err!=nil {
			return fmt.Errorf("FI PG relay %s PostgreSQL wire handshake FAILED: %w",name,err)
		}
		fmt.Printf("FI PG RELAY READY profile=%s port=%d handshake=postgresql-sslrequest\n",name,basePort+i)
	}
	signals:=make(chan os.Signal,1)
	signal.Notify(signals,syscall.SIGINT,syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	for _,l:=range listeners {_=l.Close()}
	// Children still serving clients are allowed to finish; the benchmark
	// runner stops new work before terminating this relay.
	_ = wg
	return nil
}

func main() {
	var dial,clusterRoot,outputRoot,jailBinary string
	var basePort int
	flag.StringVar(&dial,"dial","","INTERNAL: connect from jailed child to a PostgreSQL UNIX socket")
	flag.StringVar(&clusterRoot,"cluster-root","","original isolated cluster root inside fi-dev")
	flag.StringVar(&outputRoot,"output-root","","fresh HOST result directory")
	flag.StringVar(&jailBinary,"jail-binary","/home/jwood/fi-w128-chunk-build/fi-backlog-pg-relay","jail-local executable from fi-dev build")
	flag.IntVar(&basePort,"base-port",0,"first isolated PostgreSQL port")
	flag.Parse()
	var err error
	if dial!="" {err=dialInJail(dial)} else {
		err=serve(clusterRoot,outputRoot,jailBinary,basePort)
	}
	if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
