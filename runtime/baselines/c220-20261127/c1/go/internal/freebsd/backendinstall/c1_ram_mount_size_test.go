package backendinstall

import "testing"

func TestC1RAMFilesystemStatfsLimit(t *testing.T){
    for _,tc:=range []struct{blocks,size uint64;want bool}{
        {1048576,4096,true}, // 4 GiB
        {786432,4096,true}, // 3 GiB
        {524288,4096,true}, // 2 GiB
        {262144,4096,false}, // 1 GiB
        {1048577,4096,false}, // over 4 GiB
        {0,4096,false},
        {1048576,0,false},
        {1,^uint64(0),false}, // adversarial overflow / unbounded mount
    }{
        err:=ValidateC1RAMFilesystemSize(tc.blocks,tc.size)
        if (err==nil)!=tc.want{
            t.Fatalf("tmpfs statfs blocks=%d blocksize=%d want=%t error=%v",
                tc.blocks,tc.size,tc.want,err)
        }
    }
}
