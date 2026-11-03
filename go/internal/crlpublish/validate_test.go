package crlpublish

import (
 "bytes"
 "crypto/rand"
 "crypto/rsa"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "testing"
 "time"
)

func TestSignedCRLRenewalRejectsExpiredAndRollback(t *testing.T){
 now:=time.Date(2026,11,3,11,0,0,0,time.UTC)
 key,err:=rsa.GenerateKey(rand.Reader,2048);if err!=nil{t.Fatal(err)}
 template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"ISS-Root-CA"},
 NotBefore:now.Add(-24*time.Hour),NotAfter:now.AddDate(2,0,0),
 IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign}
 der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
 rootPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 root,err:=ParseRoot(rootPEM);if err!=nil{t.Fatal(err)}
 makeCRL:=func(n int64,expires time.Time) *x509.RevocationList {
  t.Helper()
  signed,err:=x509.CreateRevocationList(rand.Reader,
   &x509.RevocationList{Number:big.NewInt(n),ThisUpdate:now.Add(-time.Hour),NextUpdate:expires},
   root,key)
  if err!=nil {t.Fatal(err)}
  decoded,err:=Parse(signed);if err!=nil{t.Fatal(err)}
  return decoded
 }
 old:=makeCRL(67,now.Add(-time.Minute))
 fresh:=makeCRL(68,now.Add(7*24*time.Hour))
 if err:=Check(old,root,now,false);err!=nil{t.Fatal(err)}
 if err:=Check(old,root,now,true);err==nil{t.Fatal("expired CRL accepted")}
 if err:=Check(fresh,root,now,true);err!=nil{t.Fatal(err)}
 if err:=RejectRollback(fresh,old,now);err!=nil{t.Fatal(err)}
 if err:=RejectRollback(old,fresh,now);err==nil{t.Fatal("rollback accepted")}
 pemRaw,err:=PEM(fresh.Raw);if err!=nil{t.Fatal(err)}
 fromPEM,err:=Parse(pemRaw);if err!=nil||!bytes.Equal(fromPEM.Raw,fresh.Raw){t.Fatal("PEM round trip failed",err)}
 other:=makeCRL(68,now.Add(8*24*time.Hour))
 if err:=RejectRollback(other,fresh,now);err==nil{t.Fatal("same CRL number changed silently")}
}
