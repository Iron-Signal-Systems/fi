//go:build !freebsd

package main

import ("fmt";"os")

func main(){fmt.Fprintln(os.Stderr,"FI ZFS stage probe requires FreeBSD; no data changed");os.Exit(2)}
