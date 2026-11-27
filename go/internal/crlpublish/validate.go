// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use governed by repository LICENSE.
package crlpublish

import (
 "bytes"
 "crypto/x509"
 "encoding/asn1"
 "encoding/pem"
 "errors"
 "fmt"
 "math/big"
 "time"
)

var deltaOID=asn1.ObjectIdentifier{2,5,29,27}

// Parse accepts a single DER or PEM-encoded X.509 base CRL.
func Parse(raw []byte)(*x509.RevocationList,error){
 if b,rest:=pem.Decode(raw); b!=nil {
  if b.Type!="X509 CRL" || len(bytes.TrimSpace(rest))!=0 {return nil,errors.New("invalid X509 CRL PEM")}
  raw=b.Bytes
 }
 if len(raw)==0 || len(raw)>4<<20 {return nil,errors.New("invalid CRL size")}
 return x509.ParseRevocationList(raw)
}

func ParseRoot(pemBytes []byte)(*x509.Certificate,error){
 b,rest:=pem.Decode(pemBytes)
 if b==nil || b.Type!="CERTIFICATE" || len(bytes.TrimSpace(rest))!=0 {return nil,errors.New("one PEM root certificate required")}
 root,err:=x509.ParseCertificate(b.Bytes)
 if err!=nil{return nil,err}
 if !root.BasicConstraintsValid || !root.IsCA ||
  root.KeyUsage & (x509.KeyUsageCertSign|x509.KeyUsageCRLSign) !=
   x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
   return nil,errors.New("FI root CA missing required CA and CRL signing properties")
 }
 if err:=root.CheckSignatureFrom(root);err!=nil {return nil,fmt.Errorf("root CA self-signature: %w",err)}
 return root,nil
}

func Check(crl *x509.RevocationList,root *x509.Certificate,now time.Time,requireFresh bool)error{
 if crl==nil || root==nil || now.IsZero() {return errors.New("CRL, issuer and clock required")}
 if crl.Number==nil || crl.Number.Sign()<0 {return errors.New("CRL number required")}
 for _,e:=range crl.Extensions{if e.Id.Equal(deltaOID){return errors.New("delta CRL unsupported")}}
 if !bytes.Equal(crl.RawIssuer,root.RawSubject){return errors.New("CRL issuing CA mismatch")}
 if err:=crl.CheckSignatureFrom(root);err!=nil{return fmt.Errorf("CRL signature invalid: %w",err)}
 if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() ||
  !crl.NextUpdate.After(crl.ThisUpdate) {return errors.New("invalid CRL update times")}
 if requireFresh && (crl.ThisUpdate.After(now) || !crl.NextUpdate.After(now)){
  return fmt.Errorf("CRL not current: nextUpdate=%s",crl.NextUpdate.UTC().Format(time.RFC3339))
 }
 return nil
}

func RejectRollback(incoming,previous *x509.RevocationList,now time.Time)error{
 if incoming==nil || previous==nil {return errors.New("CRL comparison requires both documents")}
 if incoming.Number.Cmp(previous.Number)<0 || incoming.ThisUpdate.Before(previous.ThisUpdate) ||
  incoming.NextUpdate.Before(previous.NextUpdate) {return errors.New("CRL rollback rejected")}
 if incoming.Number.Cmp(previous.Number)==0 && !bytes.Equal(incoming.Raw,previous.Raw){
  return errors.New("CRL number unchanged but content differs")
 }
 if incoming.Number.Cmp(previous.Number)>0 && !incoming.NextUpdate.After(previous.NextUpdate){
  return errors.New("new CRL number did not advance nextUpdate")
 }
 if !incoming.NextUpdate.After(now){return errors.New("replacement CRL already expired")}
 return nil
}
func Number(n *big.Int)string{if n==nil{return ""};return n.Text(16)}
func PEM(raw []byte)([]byte,error){
 c,err:=Parse(raw);if err!=nil{return nil,err}
 return pem.EncodeToMemory(&pem.Block{Type:"X509 CRL",Bytes:c.Raw}),nil
}
