package main
import ("crypto/tls";"fmt";"net";"time";"os")
func main(){
 for _,h:=range os.Args[1:]{
  for i:=0;i<3;i++{
   t0:=time.Now()
   c,err:=net.DialTimeout("tcp",h+":443",5*time.Second); if err!=nil{fmt.Println(err);continue}
   t1:=time.Now()
   t:=tls.Client(c,&tls.Config{ServerName:h,InsecureSkipVerify:true,MaxVersion:tls.VersionTLS12})
   if err:=t.Handshake();err!=nil{fmt.Println(err);continue}
   t2:=time.Now()
   t.Write([]byte("GET /derp HTTP/1.1\r\nHost: "+h+"\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"))
   b:=make([]byte,512);t.Read(b)
   t3:=time.Now()
   fmt.Printf("%s tcp=%dms tls12=%dms upgrade=%dms total=%dms\n",h,t1.Sub(t0).Milliseconds(),t2.Sub(t1).Milliseconds(),t3.Sub(t2).Milliseconds(),t3.Sub(t0).Milliseconds())
   c.Close()
  }}}
