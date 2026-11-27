//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// FI backend telemetry rebuild: 15s source sampling / 5m separate recorder.
// Source NEVER writes SQL. Recorder has no fi database credentials.
package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "os"
 "os/exec"
 "os/signal"
 "strings"
 "syscall"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/telemetrybackend"
 "github.com/jackc/pgx/v5"
)

type commandSpec struct{label string; name string; args []string}
var nativeCommands=[]commandSpec{
 {"cpu","/sbin/sysctl",[]string{"kern.cp_time","hw.ncpu","hw.physmem","hw.pagesize"}},
 {"memory","/sbin/sysctl",[]string{"vm.stats.vm.v_free_count","vm.stats.vm.v_inactive_count","vm.stats.vm.v_wire_count","vm.stats.vm.v_active_count"}},
 {"swap","/usr/sbin/swapinfo",[]string{"-k"}},
 {"zfs_pools","/sbin/zpool",[]string{"list","-p","-o","name,size,allocated,free,health"}},
 {"zfs_io","/sbin/zpool",[]string{"iostat","-v","-p","fast","work","zroot"}},
 {"zfs_latency","/sbin/zpool",[]string{"iostat","-l","-v","-p","fast","work","zroot"}},
 {"arc","/sbin/sysctl",[]string{"kstat.zfs.misc.arcstats.size","kstat.zfs.misc.arcstats.hits","kstat.zfs.misc.arcstats.misses","kstat.zfs.misc.arcstats.c"}},
 {"processes","/bin/ps",[]string{"-axo","pid,jid,user,comm,pcpu,rss,vsz,state"}},
 {"interfaces","/usr/bin/netstat",[]string{"-ibdn"}},
}
type boundedBuffer struct {bytes.Buffer; limit int}
func (b *boundedBuffer)Write(p []byte)(int,error){
 if b.Len()+len(p)>b.limit{return 0,errors.New("FI telemetry: OS command output exceeded bound")}
 return b.Buffer.Write(p)
}
func fixedOSObservation(ctx context.Context,s commandSpec)map[string]interface{}{
 sub,cancel:=context.WithTimeout(ctx,3*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(sub,s.name,s.args...)
 output:=&boundedBuffer{limit:256*1024}
 cmd.Stdout=output
 cmd.Stderr=output
 if err:=cmd.Run();err!=nil{
  return map[string]interface{}{"status":"NOT_OBSERVED","reason":err.Error()}
 }
 return map[string]interface{}{"status":"OK","text":output.String()}
}
const pgStatsQuery = "SELECT jsonb_build_object("+
 "'database',(SELECT to_jsonb(d) FROM pg_stat_database d WHERE datname='fi'),"+
 "'wal',(SELECT to_jsonb(w) FROM pg_stat_wal w),"+
 "'checkpointer',(SELECT to_jsonb(c) FROM pg_stat_checkpointer c),"+
 "'background_writer',(SELECT to_jsonb(b) FROM pg_stat_bgwriter b),"+
 "'settings',(SELECT jsonb_object_agg(name,jsonb_build_object('setting',setting,'unit',unit)) "+
 " FROM pg_settings WHERE name IN ('max_wal_size','wal_buffers','checkpoint_timeout',"+
 " 'checkpoint_completion_target','shared_buffers','fsync','synchronous_commit','full_page_writes')),"+
 "'activity',(SELECT coalesce(jsonb_agg(jsonb_build_object('backend_type',a.backend_type,"+
 "'state',a.state,'wait_event_type',a.wait_event_type,'wait_event',a.wait_event)), '[]'::jsonb) "+
 "FROM pg_stat_activity a WHERE a.datname='fi'))::text"

func postgresObservation(ctx context.Context,dsn string)map[string]interface{}{
 if dsn=="" {return map[string]interface{}{"status":"NOT_OBSERVED","reason":"no read-only fi monitor connection configured"}}
 sub,cancel:=context.WithTimeout(ctx,5*time.Second)
 defer cancel()
 conn,err:=pgx.Connect(sub,dsn)
 if err!=nil{return map[string]interface{}{"status":"NOT_OBSERVED","reason":"monitor connection unavailable"}}
 defer conn.Close(context.Background())
 var raw string
 if err=conn.QueryRow(sub,pgStatsQuery).Scan(&raw);err!=nil{
  return map[string]interface{}{"status":"NOT_OBSERVED","reason":"read-only statistics query unavailable"}
 }
 var stats interface{}
 if err:=json.Unmarshal([]byte(raw),&stats);err!=nil{
  return map[string]interface{}{"status":"NOT_OBSERVED","reason":"invalid PostgreSQL statistics JSON"}
 }
 return map[string]interface{}{"status":"OK","data":stats}
}
func onceSample(ctx context.Context,spool,host,run,source,revision,pgDSN string,
 sequence uint64,prior time.Time)error{
 observed:=time.Now().UTC()
 fields:=map[string]interface{}{"scope":source,"revision":revision}
 for _,command:=range nativeCommands{
  fields[command.label]=fixedOSObservation(ctx,command)
 }
 fields["postgresql"]=postgresObservation(ctx,pgDSN)
 if !prior.IsZero()&&observed.Sub(prior)>25*time.Second {
  fields["sampling_continuity"]=map[string]interface{}{
   "status":"GAP","since":prior.UTC().Format(time.RFC3339Nano),
   "until":observed.Format(time.RFC3339Nano),
   "reason":"collector_schedule_interruption",
  }
 }else{
  fields["sampling_continuity"]=map[string]interface{}{"status":"OK"}
 }
 _,err:=telemetrybackend.Put(spool,telemetrybackend.Entry{
  Version:1,Host:host,RunID:run,Sequence:sequence,
  Stream:"samples",ObservedAt:observed,Data:fields,
 })
 if err!=nil{return fmt.Errorf("durable sample custody: %w",err)}
 log.Printf("FI TELEMETRY SAMPLE durable=true source=%s sequence=%d observed_at=%s",
  source,sequence,observed.Format(time.RFC3339Nano))
 return nil
}
func addGap(spool,host,run,source,revision,since string)error{
 if since==""{return nil}
 t,err:=time.Parse(time.RFC3339Nano,since)
 if err!=nil{return err}
 now:=time.Now().UTC()
 if !t.Before(now){return errors.New("FI telemetry: gap begin is not before current time")}
 _,err=telemetrybackend.Put(spool,telemetrybackend.Entry{
  Version:1,Host:host,RunID:run,Sequence:0,
  Stream:"events",ObservedAt:now,
  Data:map[string]interface{}{
   "scope":source,"revision":revision,"event":"TelemetryContinuityGap",
   "start_utc":t.UTC(),"end_utc":now,
   "reason":"collector_not_operational_or_not_verified",
   "sample_count":"NOT_OBSERVED",
  },
 })
 return err
}
func collect(ctx context.Context,spool,source,revision,pgDSN,gapSince string,interval time.Duration,one bool)error {
 if err:=telemetrybackend.IsSafeSpool(spool);err!=nil{return err}
 if interval!=15*time.Second{return errors.New("FI telemetry: source cadence must be 15 seconds")}
 host,err:=os.Hostname();if err!=nil{return err}
 run:=time.Now().UTC().Format("20060102T150405.000000000Z")+"-"+source
 if err:=addGap(spool,host,run,source,revision,gapSince);err!=nil{return err}
 var seq uint64
 var prior time.Time
 ticker:=time.NewTicker(interval)
 defer ticker.Stop()
 for {
  if err:=ctx.Err();err!=nil{return nil}
  now:=time.Now().UTC()
  seq++
  if err:=onceSample(ctx,spool,host,run,source,revision,pgDSN,seq,prior);err!=nil{return err}
  prior=now
  if one{return nil}
  select{
   case <-ctx.Done():return nil
   case <-ticker.C:
  }
 }
}
func entryBatchDigest(items []telemetrybackend.Pending)string{
 h:=sha256.New()
 for _,p:=range items{io.WriteString(h,p.SHA256+"\n")}
 return hex.EncodeToString(h.Sum(nil))
}
func flush(ctx context.Context,spool,dsn string)(int,error){
 pending,err:=telemetrybackend.ReadPending(spool,256)
 if err!=nil{return 0,err}
 if len(pending)==0{return 0,nil}
 if dsn==""{return 0,errors.New("FI telemetry recorder: separate fi_telemetry database DSN missing")}
 sub,cancel:=context.WithTimeout(ctx,60*time.Second)
 defer cancel()
 conn,err:=pgx.Connect(sub,dsn)
 if err!=nil{return 0,fmt.Errorf("FI telemetry recorder unavailable (spool retained): %w",err)}
 defer conn.Close(context.Background())
 var db,entryTable,receiptTable string
 err=conn.QueryRow(sub,"SELECT current_database(),"+
  " coalesce(to_regclass('telemetry_v2.entry')::text,''),"+
  " coalesce(to_regclass('telemetry_v2.delivery_receipt')::text,'')").Scan(&db,&entryTable,&receiptTable)
 if err!=nil{return 0,err}
 if db!="fi_telemetry"||entryTable!="telemetry_v2.entry"||
 receiptTable!="telemetry_v2.delivery_receipt" {
  return 0,errors.New("FI telemetry recorder: wrong database/schema; no custody retired")
 }
 tx,err:=conn.Begin(sub);if err!=nil{return 0,err}
 defer tx.Rollback(context.Background())
 for _,p:=range pending{
  _,err=tx.Exec(sub,
   "INSERT INTO telemetry_v2.entry(entry_id,source_host,run_id,stream,observed_at,payload) "+
   "VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(entry_id) DO NOTHING",
   p.SHA256,p.Entry.Host,p.Entry.RunID,p.Entry.Stream,p.Entry.ObservedAt,string(p.Data))
  if err!=nil{return 0,err}
 }
 digest:=entryBatchDigest(pending)
 _,err=tx.Exec(sub,"INSERT INTO telemetry_v2.delivery_receipt"+
  "(batch_sha256,item_count) VALUES($1,$2) ON CONFLICT(batch_sha256) DO NOTHING",
  digest,len(pending))
 if err!=nil{return 0,err}
 var recordedCount int
 if err=tx.QueryRow(sub,"SELECT item_count FROM telemetry_v2.delivery_receipt WHERE batch_sha256=$1",
   digest).Scan(&recordedCount);err!=nil{return 0,err}
 if recordedCount!=len(pending){return 0,errors.New("FI telemetry: conflicting receipt count")}
 if err=tx.Commit(sub);err!=nil{return 0,err}
 // The SQL commit is durable before local samples can be retired.
 if err=telemetrybackend.Retire(spool,pending);err!=nil{
  return 0,fmt.Errorf("SQL committed, local retirement incomplete (safe to retry): %w",err)
 }
 log.Printf("FI TELEMETRY COMMITTED database=fi_telemetry stream=version2 entries=%d batch_sha256=%s",
  len(pending),digest)
 return len(pending),nil
}
func upload(ctx context.Context,spool,dsn string,interval time.Duration,one bool)error{
 if err:=telemetrybackend.IsSafeSpool(spool);err!=nil{return err}
 if interval!=5*time.Minute{return errors.New("FI telemetry: upload cadence must be 5 minutes")}
 for{
  if ctx.Err()!=nil{return nil}
  // Oldest first, drain bounded batches; a failure does not delete custody.
  for{
   n,err:=flush(ctx,spool,dsn)
   if err!=nil{log.Printf("FI TELEMETRY UPLOAD UNAVAILABLE: %v",err);break}
   if n==0{break}
   if n<256{break}
  }
  if one{return nil}
  timer:=time.NewTimer(interval)
  select{
   case <-ctx.Done():timer.Stop();return nil
   case <-timer.C:
  }
 }
}
func main(){
 mode:=flag.String("mode","","collect or upload")
 spool:=flag.String("spool","","absolute existing private durable JSONL custody directory")
 source:=flag.String("source","c220-host","host or fi-sor")
 revision:=flag.String("revision","","exact audited FI Git commit SHA")
 gapSince:=flag.String("gap-since","","optional observed UTC gap beginning")
 once:=flag.Bool("once",false,"single sample or one upload flush")
 flag.Parse()
 if flag.NArg()!=0{log.Fatal("FI telemetry: positional arguments forbidden")}
 if os.Geteuid()==0{log.Fatal("FI telemetry: root execution forbidden")}
 if *spool==""{log.Fatal("FI telemetry: spool path required")}
 ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
 defer stop()
 var err error
 switch *mode{
 case "collect":
  if len(*revision)!=40||strings.ContainsAny(*revision," \n\r\t"){log.Fatal("FI telemetry: 40 character SHA required")}
  if _,e:=hex.DecodeString(*revision);e!=nil{log.Fatal("FI telemetry: invalid SHA hex")}
  err=collect(ctx,*spool,*source,*revision,os.Getenv("FI_TELEMETRY_MONITOR_DSN"),*gapSince,15*time.Second,*once)
 case "upload":
  if *gapSince!=""{log.Fatal("FI telemetry: gap-since only applies to collectors")}
  err=upload(ctx,*spool,os.Getenv("FI_TELEMETRY_RECORDER_DSN"),5*time.Minute,*once)
 default:
  err=errors.New("FI telemetry: choose -mode collect or upload")
 }
 if err!=nil{log.Fatal(err)}
}
