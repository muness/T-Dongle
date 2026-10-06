package main
import ("crypto/tls";"fmt";"net";"os";"bufio";"crypto/ecdsa";"crypto/rsa";"time";"sync")
func main(){
 f,_:=os.Open("hosts.txt");sc:=bufio.NewScanner(f);var hs []string
 for sc.Scan(){hs=append(hs,sc.Text())}
 var wg sync.WaitGroup;var mu sync.Mutex
 sem:=make(chan struct{},12)
 res:=map[string]int{}
 for _,h:=range hs{wg.Add(1);sem<-struct{}{};go func(host string){defer wg.Done();defer func(){<-sem}()
  d:=net.Dialer{Timeout:6*time.Second}
  raw,err:=tls.DialWithDialer(&d,"tcp",host+":443",&tls.Config{InsecureSkipVerify:true,MaxVersion:tls.VersionTLS12})
  if err!=nil{mu.Lock();res["ERR"]++;mu.Unlock();return}
  st:=raw.ConnectionState();tot:=0;desc:=""
  for _,c:=range st.PeerCertificates{tot+=len(c.Raw)
   switch k:=c.PublicKey.(type){case *ecdsa.PublicKey:desc+=" ec-"+k.Curve.Params().Name;case *rsa.PublicKey:desc+=fmt.Sprintf(" rsa%d",k.N.BitLen());default:desc+=" other"}
   desc+="/"+c.Issuer.CommonName}
  key:=fmt.Sprintf("%s n=%d |%s",tls.CipherSuiteName(st.CipherSuite),len(st.PeerCertificates),desc)
  _=tot
  mu.Lock();res[key]++;mu.Unlock();raw.Close()}(h)}
 wg.Wait()
 for k,v:=range res{fmt.Println(v,k)}
}
