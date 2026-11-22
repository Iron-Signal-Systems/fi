package backendinstall

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestC1SoRServiceIdentityExactJailBoundary(t *testing.T){
    root:=t.TempDir()
    config:=Config{values:map[string]string{
        "FI_SOR_DB_ROOT":root,"FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
    }}
    if err:=os.MkdirAll(filepath.Join(root,"etc"),0755);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(root,"etc/group"),
        []byte("fi-sor:*:4100:\n"),0644);err!=nil{t.Fatal(err)}
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

func TestC1ExistingC220SocketGroupIsReusedNotReplaced(t *testing.T){
    root:=t.TempDir()
    if err:=os.MkdirAll(filepath.Join(root,"etc"),0755);err!=nil{t.Fatal(err)}
    groups:=filepath.Join(root,"etc/group")
    passwd:=filepath.Join(root,"etc/master.passwd")
    if err:=os.WriteFile(groups,[]byte("postgres:*:770:\nfi-ingest-socket:*:4100:postgres\n"),0644);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(passwd,[]byte("postgres:*:770:770::0:0:Postgres:/nonexistent:/usr/sbin/nologin\n"),0600);err!=nil{t.Fatal(err)}
    cfg:=Config{values:map[string]string{
        "FI_SOR_DB_ROOT":root,"FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
    }}
    spec,err:=c1SoRIdentitySpec(cfg)
    if err!=nil{t.Fatal(err)}
    if spec.User!="fi-sor"||spec.Group!="fi-ingest-socket"||spec.UID!=4100||spec.GID!=4100{
        t.Fatalf("existing C220 PostgreSQL socket group was not reused: %+v",spec)
    }
    calls:=0
    fake:=systemIdentityMutator{execute:func(cmd string,args ...string)([]byte,error){
        calls++
        joined:=strings.Join(args," ")
        if cmd!="/usr/sbin/pw" || !strings.Contains(joined," useradd ") ||
            !strings.Contains(joined,"-g fi-ingest-socket") ||
            !strings.Contains(joined,"-n fi-sor") ||
            !strings.Contains(joined,"-u 4100") ||
            strings.Contains(joined,"groupadd"){
            t.Fatalf("unsafe C220 service identity mutation: %s %s",cmd,joined)
        }
        return nil,nil
    }}
    if err=c1AddSoRUserToExistingSocketGroup(fake,spec);err!=nil{t.Fatal(err)}
    if calls!=1{t.Fatalf("expected single useradd, got %d mutator calls",calls)}
    // Simulate FreeBSD pw useradd: the original socket group remains intact.
    if err=os.WriteFile(passwd,[]byte("postgres:*:770:770::0:0:Postgres:/nonexistent:/usr/sbin/nologin\n"+
        "fi-sor:*:4100:4100::0:0:FI:/nonexistent:/usr/sbin/nologin\n"),0600);err!=nil{t.Fatal(err)}
    if err=VerifyC1SoRIdentity(cfg);err!=nil{t.Fatal(err)}
    if err=c1AddSoRUserToExistingSocketGroup(fake,spec);err==nil{
        t.Fatal("duplicate user provisioning was permitted")
    }
    if calls!=1{t.Fatal("duplicate provisioning invoked mutator")}
}
func TestC1SoRIdentityRejectsForeignC220GIDCollision(t *testing.T){
    root:=t.TempDir()
    if err:=os.MkdirAll(filepath.Join(root,"etc"),0755);err!=nil{t.Fatal(err)}
    cfg:=Config{values:map[string]string{
        "FI_SOR_DB_ROOT":root,"FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
    }}
    path:=filepath.Join(root,"etc/group")
    if err:=os.WriteFile(path,[]byte("unrelated:*:4100:\n"),0644);err!=nil{t.Fatal(err)}
    if _,err:=c1SoRIdentitySpec(cfg);err==nil{
        t.Fatal("foreign numeric GID was accepted as C1 runtime identity")
    }
    if err:=os.WriteFile(path,[]byte("fi-ingest-socket:*:4100:postgres\nfi-sor:*:4100:\n"),0644);err!=nil{t.Fatal(err)}
    if _,err:=c1SoRIdentitySpec(cfg);err==nil{
        t.Fatal("duplicate GID was accepted as C1 service identity")
    }
}
