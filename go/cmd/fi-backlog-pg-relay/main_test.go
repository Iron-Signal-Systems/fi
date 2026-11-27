package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRelayPostgresWireHandshake(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"postgres.sock")
	listener,err:=net.Listen("unix",path)
	if err!=nil {t.Fatal(err)}
	defer listener.Close()
	done:=make(chan error,1)
	go func(){
		conn,err:=listener.Accept()
		if err!=nil {done<-err;return}
		defer conn.Close()
		var b [8]byte
		_,err=io.ReadFull(conn,b[:])
		if err!=nil {done<-err;return}
		want:=[8]byte{0,0,0,8,4,210,22,47}
		if b!=want {done<-io.ErrUnexpectedEOF;return}
		_,err=conn.Write([]byte{'N'})
		done<-err
	}()
	if err:=probe(path);err!=nil {t.Fatal(err)}
	if err:=<-done;err!=nil {t.Fatal(err)}
}

func TestRelayRejectsUnsafeClusterRoots(t *testing.T){
	for _,v:=range []string{"","/var/tmp/fi-window-bench-1",
		"/home/jwood/fi-window-bench-../etc",
		"/home/jwood/fi-window-bench-abc/../etc",
		"home/jwood/fi-window-bench-abc"}{
		if validClusterRoot(v){t.Fatalf("accepted unsafe root %q",v)}
	}
	if !validClusterRoot("/home/jwood/fi-window-bench-20261103T090325Z"){
		t.Fatal("rejected valid disposable test root")
	}
}

func TestRelayHelperProcess(t *testing.T) {
	if os.Getenv("FI_FAKE_JAIL_TEST")!="1" {return}
	socket:=os.Args[len(os.Args)-1]
	c,err:=net.Dial("unix",socket)
	if err!=nil {os.Exit(3)}
	go func(){
		_,_=io.Copy(c,os.Stdin)
		if u,ok:=c.(*net.UnixConn);ok {_=u.CloseWrite()}
	}()
	_,err=io.Copy(os.Stdout,c)
	if err!=nil {os.Exit(4)}
	os.Exit(0)
}

func TestHostRelayToJailedPostgresWireRoundTrip(t *testing.T) {
	// Mimic jexec in process-safe PATH so the real bridgeConnection
	// launches a separate helper and forwards PostgreSQL bytes in both
	// directions. This does not require root or a FreeBSD jail in CI.
	bindir:=t.TempDir()
	fake:=filepath.Join(bindir,"jexec")
	if err:=os.WriteFile(fake,[]byte("#!/bin/sh\nshift 3\nexec \"$1\" -test.run=TestRelayHelperProcess -- \"$3\"\n"),0700);err!=nil{t.Fatal(err)}
	t.Setenv("PATH",bindir+":"+os.Getenv("PATH"))
	t.Setenv("FI_FAKE_JAIL_TEST","1")

	backendPath:=filepath.Join(t.TempDir(),"backend.sock")
	backend,err:=net.Listen("unix",backendPath)
	if err!=nil{t.Fatal(err)}
	defer backend.Close()
	backendDone:=make(chan error,1)
	go func() {
		c,err:=backend.Accept()
		if err!=nil{backendDone<-err;return}
		defer c.Close()
		var b [8]byte
		if _,err=io.ReadFull(c,b[:]);err!=nil{backendDone<-err;return}
		if b!=[8]byte{0,0,0,8,4,210,22,47}{backendDone<-io.ErrUnexpectedEOF;return}
		_,err=c.Write([]byte{'N'})
		backendDone<-err
	}()

	hostPath:=filepath.Join(t.TempDir(),"host.sock")
	host,err:=net.Listen("unix",hostPath)
	if err!=nil{t.Fatal(err)}
	defer host.Close()
	relayDone:=make(chan struct{})
	go func(){
		defer close(relayDone)
		c,err:=host.Accept()
		if err!=nil{return}
		bridgeConnection(c,os.Args[0],backendPath)
	}()
	if err:=probe(hostPath);err!=nil{t.Fatal(err)}
	if err:=<-backendDone;err!=nil{t.Fatal(err)}
	<-relayDone
}
