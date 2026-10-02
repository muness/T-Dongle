package main
import (
 "crypto/tls"
 "encoding/binary"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "os"
 "os/exec"
 "strings"
 "time"
)
func run(client string, duplicate bool) {
 srv:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  if r.Method!="POST" {panic("bad method")}
  if r.URL.Path=="/machine/register" {io.Copy(io.Discard,r.Body);fmt.Fprint(w,"{}");return}
  if r.URL.Path!="/machine/map" {panic("bad request path")}
  var request map[string]interface{};if e:=json.NewDecoder(r.Body).Decode(&request);e!=nil {panic(e)}
  if request["Stream"]!=true || request["OmitPeers"]!=false || request["Version"]!=float64(131) {panic("bad map body")}
  payload:=[]byte(`{"Node":{"Name":"fixture.ts.net","Addresses":["100.64.0.8/32"]},"Peers":[]}`)
  prefix:=make([]byte,4);binary.LittleEndian.PutUint32(prefix,uint32(len(payload)));w.Write(prefix);w.Write(payload)
 }));srv.EnableHTTP2=true;srv.StartTLS();defer srv.Close()
 c,e:=tls.Dial("tcp",strings.TrimPrefix(srv.URL,"https://"),&tls.Config{InsecureSkipVerify:true,NextProtos:[]string{"h2"}});if e!=nil {panic(e)};defer c.Close();c.SetDeadline(time.Now().Add(8*time.Second))
 args:=[]string{};if duplicate {args=append(args,"duplicate")};cmd:=exec.Command(client,args...);cmd.Stderr=os.Stderr
 input,e:=cmd.StdinPipe();if e!=nil {panic(e)};output,e:=cmd.StdoutPipe();if e!=nil {panic(e)}
 if e=cmd.Start();e!=nil {panic(e)}
 go func(){io.Copy(c,output)}();go func(){io.Copy(input,c);input.Close()}()
 done:=make(chan error,1);go func(){done<-cmd.Wait()}()
 select {case e=<-done:if e!=nil {panic(e)};case <-time.After(10*time.Second):cmd.Process.Kill();panic("interop timeout")}
}
func main(){if len(os.Args)!=2{panic("client required")};run(os.Args[1],true);run(os.Args[1],false)}
