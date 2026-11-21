// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Private C1 B verifier. Separate OS process. No record ingestion, no
// PostgreSQL writes, no original batch SHA-256 replay.
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main(){
    if err:=recordingest.RunPrivateC1VerifyChild(context.Background(),os.Stdin);err!=nil{
        fmt.Fprintln(os.Stderr,"FI C1 B VERIFIER STOP:",err)
        os.Exit(1)
    }
}
