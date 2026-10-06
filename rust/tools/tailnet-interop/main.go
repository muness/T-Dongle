// tailnet-interop: a REAL Tailscale control server (tailscale.com/tstest/integration/testcontrol, the code the Tailscale client's own integration tests
// run against), a REAL DERP server (tailscale.com/derp/derpserver) behind a self-signed TLS listener, and optionally a REAL Tailscale node (tsnet) joined to
// that control server, for the Rust tailnet gateway's host-side interop tests. Control protocol on stdin/stdout, one command per line:
//
//	stdout first line: JSON {"control":"http://127.0.0.1:P","derp_host":"127.0.0.1","derp_port":Q,"derp_pub":"hex","noise_pub":"mkey:..."}
//	stdin  "nodes"        -> "NODES n key1 key2 ..."  (node public keys known to the control server)
//	stdin  "inmap"        -> "INMAP n"                (streaming map requests currently served)
//	stdin  "await <key>"  -> "AWAITED" once that node key has an open streaming map request (30 s timeout -> "TIMEOUT")
//	stdin  "peer"         -> starts the tsnet peer "gopeer"; prints "PEER <ip4> <nodekey>" (it echoes TCP on :7 and answers tailnet pings)
//	stdin  "fake"         -> adds a fake node to the netmap
//	stdin  "quit"
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

func main() {
	log.SetOutput(os.Stderr)
	// DERP over TLS (self-signed), the same /derp upgrade handler cmd/derper mounts.
	ds := derpserver.New(key.NewNode(), func(f string, a ...any) { log.Printf("derp: "+f, a...) })
	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(ds))
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	dsrv := httptest.NewUnstartedServer(mux)
	dsrv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	dsrv.StartTLS()
	var dport int
	fmt.Sscanf(dsrv.Listener.Addr().String()[strings.LastIndex(dsrv.Listener.Addr().String(), ":")+1:], "%d", &dport)

	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{900: {
		RegionID: 900, RegionCode: "tst", RegionName: "Test",
		Nodes: []*tailcfg.DERPNode{{Name: "900a", RegionID: 900, HostName: "127.0.0.1", IPv4: "127.0.0.1", DERPPort: dport, STUNPort: -1, InsecureForTests: true}},
	}}}
	ctl := &testcontrol.Server{DERPMap: dm, AllOnline: true, Verbose: false}
	csrv := httptest.NewServer(ctl)
	ctl.HTTPTestServer = csrv
	defer csrv.Close()

	out := bufio.NewWriter(os.Stdout)
	hello, _ := json.Marshal(map[string]any{"control": ctl.BaseURL(), "derp_host": "127.0.0.1", "derp_port": dport, "derp_pub": ds.PublicKey().UntypedHexString()})
	fmt.Fprintln(out, string(hello))
	out.Flush()

	var peer *tsnet.Server
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "nodes":
			ns := ctl.AllNodes()
			fmt.Fprintf(out, "NODES %d", len(ns))
			for _, n := range ns {
				fmt.Fprintf(out, " %s", n.Key.String())
			}
			fmt.Fprintln(out)
		case "inmap":
			fmt.Fprintf(out, "INMAP %d\n", ctl.InServeMap())
		case "await":
			var nk key.NodePublic
			if len(f) < 2 || nk.UnmarshalText([]byte(f[1])) != nil {
				fmt.Fprintln(out, "ERR bad key")
				break
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := ctl.AwaitNodeInMapRequest(ctx, nk); err != nil {
				fmt.Fprintln(out, "TIMEOUT")
			} else {
				fmt.Fprintln(out, "AWAITED")
			}
			cancel()
		case "fake":
			ctl.AddFakeNode()
			fmt.Fprintln(out, "OK")
		case "peer":
			peer = &tsnet.Server{Hostname: "gopeer", ControlURL: ctl.BaseURL(), Ephemeral: true, AuthKey: "tskey-fake", Dir: mustTemp(), Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
			st, err := peer.Up(context.Background())
			if err != nil {
				fmt.Fprintf(out, "ERR %v\n", err)
				break
			}
			ln, err := peer.Listen("tcp", ":7")
			if err == nil {
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
			}
			fmt.Fprintf(out, "PEER %s %s\n", st.TailscaleIPs[0], st.Self.PublicKey.String())
		case "quit":
			if peer != nil {
				peer.Close()
			}
			out.Flush()
			return
		default:
			fmt.Fprintln(out, "ERR unknown")
		}
		out.Flush()
	}
}

func mustTemp() string {
	d, err := os.MkdirTemp("", "tsnet-gopeer")
	if err != nil {
		panic(err)
	}
	return d
}
