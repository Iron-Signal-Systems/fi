package backendinstall

import (
    "os"
    "path/filepath"
    "testing"
)

func TestC1SoRServiceIdentityExactJailBoundary(t *testing.T){
    root:=t.TempDir()
    config:=Config{values:map[string]string{
        "FI_SOR_DB_ROOT":root,"FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
    }}
    spec,err:=c1SoRIdentitySpec(config)
    if err!=nil{t.Fatal(err)}
    if spec.User!="fi-sor"||spec.Group!="fi-sor"||spec.Root!=root||
        spec.UID!=4100||spec.GID!=4100{
        t.Fatalf("C1 SQL identity installed in wrong jail: %+v",spec)
    }
    if err=os.MkdirAll(filepath.Join(root,"etc"),0755);err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(root,"etc/master.passwd"),[]byte(
        "fi-sor:*:4100:4100::0:0:FI:/nonexistent:/usr/sbin/nologin\n"),0600);err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(root,"etc/group"),[]byte("fi-sor:*:4100:\n"),0644);err!=nil{t.Fatal(err)}
    if err=VerifyC1SoRIdentity(config);err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(root,"etc/group"),[]byte("foreign:*:4100:\n"),0644);err!=nil{t.Fatal(err)}
    if err=VerifyC1SoRIdentity(config);err==nil{t.Fatal("FI C1 accepted foreign GID collision")}
}
func TestC1SoRServiceIdentityRejectsInvalidRoot(t *testing.T){
    config:=Config{values:map[string]string{
        "FI_SOR_DB_ROOT":"/","FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
    }}
    if _,err:=c1SoRIdentitySpec(config);err==nil{
        t.Fatal("FI C1 service user could be installed in FreeBSD host root")
    }
    config.values["FI_SOR_DB_ROOT"]=filepath.Join(t.TempDir(),"nonexistent")
    if _,err:=c1SoRIdentitySpec(config);err==nil{
        t.Fatal("FI C1 service user installed into absent jail root")
    }
}
