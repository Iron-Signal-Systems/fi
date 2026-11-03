package main

import (
	"io"
	"net"
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
