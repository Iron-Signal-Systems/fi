// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 development rc services are installed OFF by default. This file
// deliberately does not modify the deployed receiver or fi-ingest-worker
// installer, PostgreSQL settings or any populated authoritative SoR data.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const c1IngestRuntimeConfig = "# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-ingest-runtime-config\n# DEVELOPMENT ONLY. Defaults reject activation.\nfi_c1_ingest_enable=\"NO\"\nfi_c1_ingest_source_id=\"\"\nfi_c1_ingest_generation_id=\"\"\n# Choose exactly one: generation_id or continuous signed receiver READY queue.\nfi_c1_ingest_ready_root=\"\"\nfi_c1_ingest_ready_batch_size=\"16\"\nfi_c1_ingest_poll_interval=\"5s\"\nfi_c1_ingest_custody_root=\"\"\nfi_c1_ingest_recorded_root=\"\"\nfi_c1_ingest_source_namespaces=\"NO\"\nfi_c1_ingest_sor_address=\"\"\nfi_c1_ingest_sor_dns=\"\"\nfi_c1_ingest_shared_ram_dir=\"/var/run/fi-c1-handoff\"\nfi_c1_ingest_tls_cert=\"\"\nfi_c1_ingest_tls_key=\"\"\nfi_c1_ingest_tls_ca=\"\"\nfi_c1_ingest_start_batch=\"0\"\n"
const c1SoRRuntimeConfig = "# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-sor-runtime-config\n# DEVELOPMENT ONLY. Defaults reject activation.\nfi_c1_sor_enable=\"NO\"\nfi_c1_sor_bind=\"\"\nfi_c1_sor_postgres_local=\"\"\n# REQUIRED distinct fi-sor-only PostgreSQL canonical publisher identity.\nfi_c1_sor_postgres_publisher_local=\"\"\n# Local Unix-socket SCRAM passfile with separate fi_ingest + fi_c1_publisher entries.\n# File mode 0600, fi-sor-owned; never available in fi-ingest jail.\nfi_c1_sor_pgpass=\"\"\nfi_c1_sor_shared_ram_dir=\"/var/run/fi-c1-handoff\"\nfi_c1_sor_custody_root=\"\"\nfi_c1_sor_recorded_root=\"\"\nfi_c1_sor_source_namespaces=\"NO\"\nfi_c1_sor_tls_cert=\"\"\nfi_c1_sor_tls_key=\"\"\nfi_c1_sor_tls_ca=\"\"\nfi_c1_sor_ingest_dns=\"\"\nfi_c1_sor_sql_workers_max=\"32\"\nfi_c1_sor_reconcile_private_replay=\"NO\"\n"
const c1IngestRuntimeRunner = "#!/bin/sh\n# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-ingest-runner\nset -eu\nverify_mode=NO\ncase \"${1:-}\" in\n  --verify)\n    [ \"$#\" -eq 1 ] || { echo \"C1 read-only runner accepts only --verify\" >&2; exit 1; }\n    verify_mode=YES\n    ;;\n  \"\")\n    [ \"$#\" -eq 0 ] || { echo \"C1 runner refuses unrecognized arguments\" >&2; exit 1; }\n    ;;\n  *)\n    echo \"C1 runner refuses unrecognized arguments\" >&2\n    exit 1\n    ;;\nesac\nCONFIG=\"/etc/rc.conf.d/fi_c1_ingest\"\nBINARY=\"/usr/local/sbin/fi-c1-ingest-worker\"\nfail(){ printf 'fi-c1-ingest: %s\\n' \"$*\" >&2; exit 1; }\n[ -f \"$CONFIG\" ] && [ ! -L \"$CONFIG\" ] || fail \"FI C1 config absent/unsafe\"\n. \"$CONFIG\"\n[ -x \"$BINARY\" ] || fail \"FI C1 signed reader executable missing\"\n[ -n \"$fi_c1_ingest_source_id\" ] || fail \"required C1 parameter absent: fi_c1_ingest_source_id\"\n# Exactly one intake mode. Continuous READY mode polls original receiver\n# custody without ever opening PostgreSQL inside fi-ingest.\nif [ -n \"${fi_c1_ingest_generation_id:-}\" ] && [ -n \"${fi_c1_ingest_ready_root:-}\" ]; then\n    fail \"choose generation-id OR continuous signed READY queue, not both\"\nfi\nif [ -z \"${fi_c1_ingest_generation_id:-}\" ] && [ -z \"${fi_c1_ingest_ready_root:-}\" ]; then\n    fail \"missing original signed generation-id or READY queue root\"\nfi\n[ -n \"$fi_c1_ingest_custody_root\" ] || fail \"required C1 parameter absent: fi_c1_ingest_custody_root\"\n[ -n \"$fi_c1_ingest_recorded_root\" ] || fail \"required C1 parameter absent: fi_c1_ingest_recorded_root\"\n[ -n \"$fi_c1_ingest_sor_address\" ] || fail \"required C1 parameter absent: fi_c1_ingest_sor_address\"\n[ -n \"$fi_c1_ingest_sor_dns\" ] || fail \"required C1 parameter absent: fi_c1_ingest_sor_dns\"\n[ -n \"$fi_c1_ingest_shared_ram_dir\" ] || fail \"required C1 parameter absent: fi_c1_ingest_shared_ram_dir\"\n[ -n \"$fi_c1_ingest_tls_cert\" ] || fail \"required C1 parameter absent: fi_c1_ingest_tls_cert\"\n[ -n \"$fi_c1_ingest_tls_key\" ] || fail \"required C1 parameter absent: fi_c1_ingest_tls_key\"\n[ -n \"$fi_c1_ingest_tls_ca\" ] || fail \"required C1 parameter absent: fi_c1_ingest_tls_ca\"\nset -- -source-id \"$fi_c1_ingest_source_id\" \\\n    -custody-root \"$fi_c1_ingest_custody_root\" -recorded-root \"$fi_c1_ingest_recorded_root\" \\\n    -sor-address \"$fi_c1_ingest_sor_address\" -sor-server-dns \"$fi_c1_ingest_sor_dns\" \\\n    -shared-ram-dir \"$fi_c1_ingest_shared_ram_dir\" \\\n    -tls-cert \"$fi_c1_ingest_tls_cert\" -tls-key \"$fi_c1_ingest_tls_key\" -tls-ca \"$fi_c1_ingest_tls_ca\" \\\n    -start-batch \"${fi_c1_ingest_start_batch:-0}\"\nif [ -n \"${fi_c1_ingest_generation_id:-}\" ]; then\n    set -- \"$@\" -generation-id \"$fi_c1_ingest_generation_id\"\nelse\n    [ \"${fi_c1_ingest_start_batch:-0}\" = 0 ] || fail \"READY queue must start at original signed batch zero\"\n    set -- \"$@\" -ready-root \"$fi_c1_ingest_ready_root\" \\\n        -ready-batch-size \"${fi_c1_ingest_ready_batch_size:-16}\" \\\n        -poll-interval \"${fi_c1_ingest_poll_interval:-5s}\"\nfi\ncase \"${fi_c1_ingest_source_namespaces:-NO}\" in\nYES) set -- \"$@\" -source-namespaces ;;\nNO) ;;\n*) fail \"invalid source namespace mode\" ;;\nesac\nif [ \"$verify_mode\" = YES ]; then\n    # Use the exact production arguments but never open a C1 listener,\n    # send a signed generation, create a RAM object, or write PostgreSQL.\n    set -- \"$@\" -preflight\nfi\nexec \"$BINARY\" \"$@\"\n"
const c1SoRRuntimeRunner = "#!/bin/sh\n# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-sor-runner\nset -eu\nverify_mode=NO\ncase \"${1:-}\" in\n  --verify)\n    [ \"$#\" -eq 1 ] || { echo \"C1 read-only runner accepts only --verify\" >&2; exit 1; }\n    verify_mode=YES\n    ;;\n  \"\")\n    [ \"$#\" -eq 0 ] || { echo \"C1 runner refuses unrecognized arguments\" >&2; exit 1; }\n    ;;\n  *)\n    echo \"C1 runner refuses unrecognized arguments\" >&2\n    exit 1\n    ;;\nesac\nCONFIG=\"/etc/rc.conf.d/fi_c1_sor\"\nBINARY=\"/usr/local/sbin/fi-c1-sor-worker\"\nfail(){ printf 'fi-c1-sor: %s\\n' \"$*\" >&2; exit 1; }\n[ -f \"$CONFIG\" ] && [ ! -L \"$CONFIG\" ] || fail \"FI C1 config absent/unsafe\"\n. \"$CONFIG\"\n[ -x \"$BINARY\" ] || fail \"FI C1 SoR executable missing\"\nif [ -n \"${fi_c1_sor_pgpass:-}\" ]; then\n    [ -f \"$fi_c1_sor_pgpass\" ] && [ ! -L \"$fi_c1_sor_pgpass\" ] && [ -r \"$fi_c1_sor_pgpass\" ] ||\n        fail \"fi-sor PostgreSQL credentials missing, unreadable or symlinked\"\n    [ \"$(stat -f '%#Lp' \"$fi_c1_sor_pgpass\")\" = \"0600\" ] ||\n        fail \"fi-sor PostgreSQL credentials must be mode 0600\"\n    PGPASSFILE=\"$fi_c1_sor_pgpass\"\n    export PGPASSFILE\nfi\n[ -n \"$fi_c1_sor_bind\" ] || fail \"required C1 parameter absent: fi_c1_sor_bind\"\n[ -n \"$fi_c1_sor_postgres_local\" ] || fail \"required C1 parameter absent: fi_c1_sor_postgres_local\"\n[ -n \"${fi_c1_sor_postgres_publisher_local:-}\" ] || fail \"required C1 parameter absent: fi_c1_sor_postgres_publisher_local\"\n[ -n \"$fi_c1_sor_shared_ram_dir\" ] || fail \"required C1 parameter absent: fi_c1_sor_shared_ram_dir\"\n[ -n \"$fi_c1_sor_custody_root\" ] || fail \"required C1 parameter absent: fi_c1_sor_custody_root\"\n[ -n \"$fi_c1_sor_recorded_root\" ] || fail \"required C1 parameter absent: fi_c1_sor_recorded_root\"\n[ -n \"$fi_c1_sor_tls_cert\" ] || fail \"required C1 parameter absent: fi_c1_sor_tls_cert\"\n[ -n \"$fi_c1_sor_tls_key\" ] || fail \"required C1 parameter absent: fi_c1_sor_tls_key\"\n[ -n \"$fi_c1_sor_tls_ca\" ] || fail \"required C1 parameter absent: fi_c1_sor_tls_ca\"\n[ -n \"$fi_c1_sor_ingest_dns\" ] || fail \"required C1 parameter absent: fi_c1_sor_ingest_dns\"\nset -- -bind \"$fi_c1_sor_bind\" -postgres-local \"$fi_c1_sor_postgres_local\" \\\n    -postgres-publisher-local \"$fi_c1_sor_postgres_publisher_local\" \\\n    -shared-ram-dir \"$fi_c1_sor_shared_ram_dir\" \\\n    -custody-root \"$fi_c1_sor_custody_root\" -recorded-root \"$fi_c1_sor_recorded_root\" \\\n    -tls-cert \"$fi_c1_sor_tls_cert\" -tls-key \"$fi_c1_sor_tls_key\" -tls-ca \"$fi_c1_sor_tls_ca\" \\\n    -ingest-client-dns \"$fi_c1_sor_ingest_dns\" \\\n    -sql-workers-max \"${fi_c1_sor_sql_workers_max:-32}\"\ncase \"${fi_c1_sor_source_namespaces:-NO}\" in\nYES) set -- \"$@\" -source-namespaces ;;\nNO) ;;\n*) fail \"invalid source namespace mode\" ;;\nesac\ncase \"${fi_c1_sor_reconcile_private_replay:-NO}\" in\nYES) set -- \"$@\" -reconcile-private-replay ;;\nNO) ;;\n*) fail \"invalid C1 private replay opt-in\" ;;\nesac\nif [ \"$verify_mode\" = YES ]; then\n    # Use the exact production arguments but never open a C1 listener,\n    # send a signed generation, create a RAM object, or write PostgreSQL.\n    set -- \"$@\" -preflight\nfi\nexec \"$BINARY\" \"$@\"\n"
const c1IngestRuntimeRC = "#!/bin/sh\n# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-ingest-rc-service\n#\n# PROVIDE: fi_c1_ingest\n# REQUIRE: NETWORKING\n# KEYWORD: shutdown\n. /etc/rc.subr\nname=\"fi_c1_ingest\"\nrcvar=\"fi_c1_ingest_enable\"\nload_rc_config \"$name\"\n: ${fi_c1_ingest_enable:=\"NO\"}\ncommand=\"/usr/sbin/daemon\"\nprocname=\"/usr/sbin/daemon\"\npidfile=\"/var/run/fi-c1-ingest.pid\"\nrequired_files=\"/usr/local/sbin/fi-c1-ingest-worker /usr/local/libexec/fi-c1-ingest-run /etc/rc.conf.d/fi_c1_ingest\"\ncommand_args=\"-P ${pidfile} -u fi-ingest -S -T fi-c1-ingest /usr/local/libexec/fi-c1-ingest-run\"\nrun_rc_command \"$1\"\n"
const c1SoRRuntimeRC = "#!/bin/sh\n# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n# FI-ROLE: c1-sor-rc-service\n#\n# PROVIDE: fi_c1_sor\n# REQUIRE: NETWORKING\n# KEYWORD: shutdown\n. /etc/rc.subr\nname=\"fi_c1_sor\"\nrcvar=\"fi_c1_sor_enable\"\nload_rc_config \"$name\"\n: ${fi_c1_sor_enable:=\"NO\"}\ncommand=\"/usr/sbin/daemon\"\nprocname=\"/usr/sbin/daemon\"\npidfile=\"/var/run/fi-c1-sor.pid\"\nrequired_files=\"/usr/local/sbin/fi-c1-sor-worker /usr/local/libexec/fi-c1-sor-run /etc/rc.conf.d/fi_c1_sor\"\ncommand_args=\"-P ${pidfile} -u fi-sor -S -T fi-c1-sor /usr/local/libexec/fi-c1-sor-run\"\nrun_rc_command \"$1\"\n"

func buildC1DevelopmentRuntimePlan(config Config)(runtimePlan,error){
    ingest:=config.Value("FI_INGEST_ROOT")
    sor:=config.Value("FI_SOR_DB_ROOT")
    if !filepath.IsAbs(ingest)||!filepath.IsAbs(sor)||
        filepath.Clean(ingest)=="/"||filepath.Clean(sor)=="/"||
        filepath.Clean(ingest)==filepath.Clean(sor){
        return runtimePlan{},errors.New("FI C1 rc: separate absolute fi-ingest and fi-sor-db jail roots required")
    }
    for _,root:=range []string{ingest,sor}{
        info,err:=os.Lstat(root)
        if err!=nil{return runtimePlan{},err}
        if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
            return runtimePlan{},errors.New("FI C1 rc: missing or symlinked jail root")
        }
    }
    gid,err:=parsePositiveDecimal("FI_RUNTIME_GID",config.Value("FI_RUNTIME_GID"))
    if err!=nil{return runtimePlan{},err}
    parents:=[]lifecycleParentSpec{}
    files:=[]runtimeFileSpec{}
    roles:=[]struct{
        root,service,runner,rc,conf string
        user string
    }{
        {ingest,"fi_c1_ingest",c1IngestRuntimeRunner,c1IngestRuntimeRC,c1IngestRuntimeConfig,"fi-ingest"},
        {sor,"fi_c1_sor",c1SoRRuntimeRunner,c1SoRRuntimeRC,c1SoRRuntimeConfig,"fi-sor"},
    }
    for _,role:=range roles{
        parentDefs:=[]struct{dir,role string}{
            {"usr/local/libexec",role.service+"-libexec-dir"},
            {"usr/local/etc/rc.d",role.service+"-rc-dir"},
            {"etc/rc.conf.d",role.service+"-rc-config-dir"},
        }
        for _,p:=range parentDefs{
            parents=append(parents,lifecycleParentSpec{
                Path:filepath.Join(role.root,p.dir),Role:p.role,UID:0,GID:0,Mode:0755,
            })
        }
        specs:=[]struct{target,role,content string;mode os.FileMode;gid uint64}{
            {filepath.Join(role.root,"usr/local/libexec",role.service[3:]+"-run"),
                strings.ReplaceAll(strings.TrimPrefix(role.service,"fi_"),"_","-")+"-runner",role.runner,0555,0},
            {filepath.Join(role.root,"usr/local/etc/rc.d",role.service),
                strings.ReplaceAll(strings.TrimPrefix(role.service,"fi_"),"_","-")+"-rc-service",role.rc,0555,0},
            {filepath.Join(role.root,"etc/rc.conf.d",role.service),
                strings.ReplaceAll(strings.TrimPrefix(role.service,"fi_"),"_","-")+"-runtime-config",role.conf,0640,gid},
        }
        // Use the EXACT absolute runner names expected by the rc scripts;
        // not derived names which may accidentally change service targets.
        specs[0].target=filepath.Join(role.root,"usr/local/libexec",
            strings.ReplaceAll(role.service,"_","-")+"-run")
        for _,x:=range specs{
            content:=[]byte(x.content)
            if !containsExactLine(content,runtimeFileMarker)||
                !containsExactLine(content,"# FI-ROLE: "+x.role)||
                (x.mode==0640&&!strings.Contains(x.content,"_enable=\"NO\"")){
                return runtimePlan{},fmt.Errorf("FI C1 rc: invalid disabled-by-default managed runtime asset %s",x.role)
            }
            files=append(files,runtimeFileSpec{
                Role:x.role,Target:x.target,Content:content,
                Mode:x.mode,UID:0,GID:x.gid,
            })
        }
    }
    return runtimePlan{Parents:parents,Files:files},nil
}

func ApplyC1DevelopmentRuntime(config Config)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1DevelopmentRuntimePlan(config)
    if err!=nil{return err}
    if err=preclassifyRuntimePlan(plan);err!=nil{return err}
    for _,p:=range plan.Parents{
        switch state:=classifyLifecycleParent(p);state{
        case lifecycleParentDirectoryMatch:
        case lifecycleParentAbsent:
            if err=createLifecycleParent(p);err!=nil{return err}
        default:
            return fmt.Errorf("FI C1 rc: unsafe parent %s (%s)",p.Role,state)
        }
    }
    for _,f:=range plan.Files{
        switch state:=classifyRuntimeFile(f);state{
        case runtimeFileOwnedMatch:
        case runtimeFileAbsent:
            if err=publishAbsentRuntimeFile(f);err!=nil{return err}
        default:
            return fmt.Errorf("FI C1 rc: refuse changed/mutated managed service %s (%s)",f.Role,state)
        }
    }
    return verifyRuntimePlan(plan)
}
func VerifyC1DevelopmentRuntime(config Config)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1DevelopmentRuntimePlan(config)
    if err!=nil{return err}
    return verifyRuntimePlan(plan)
}
