// tailnet-interop: a REAL Tailscale control server (tailscale.com/tstest/integration/testcontrol, the code the Tailscale client's own integration tests
// run against), a REAL DERP server (tailscale.com/derp/derpserver) behind a self-signed TLS listener, and optionally a REAL Tailscale node (tsnet) joined to
// that control server, for the Rust tailnet gateway's host-side interop tests. Control protocol on stdin/stdout, one command per line:
//
//	stdout first line: JSON {"control":"http://127.0.0.1:P","derp_host":"127.0.0.1","derp_port":Q,"derp_pub":"hex","noise_pub":"mkey:..."}
//	stdin  "nodes"        -> "NODES n key1 key2 ..."  (node public keys known to the control server)
//	stdin  "inmap"        -> "INMAP n"                (streaming map requests currently served)
//	stdin  "await <key>"  -> "AWAITED" once that node key has an open streaming map request (30 s timeout -> "TIMEOUT")
//	stdin  "peer [name]"  -> starts a tsnet peer (default "gopeer"); prints "PEER <ip4> <nodekey>". It echoes TCP on :7, discards-and-counts on :9
//	                         (reads to EOF, answers "<bytes>\n") and serves HTTP on :80 (GET /bytes/<n> -> n bytes of a fixed pattern, GET / -> hello)
//	stdin  "peerclose <name>" -> closes that peer (the control server then sends a PeersChanged/PeersRemoved delta to the others)
//	stdin  "rawmap <nodekey> <json>" -> queues a raw tailcfg.MapResponse (e.g. {"PeersRemoved":[3]}) for that node's streaming map: delta tests
//	stdin  "ids"          -> "IDS name=id:nodekey ..." for every node the control server knows (node ids for PeersRemoved)
//	stdin  "eps <nodekey>" -> "EPS addr,addr,..." the endpoints the control server has for that node
//	stdin  "fake"         -> adds a fake node to the netmap
//	stdin  "quit"
//
// STUN: a real STUN responder (tailscale.com/net/stun) listens on a loopback UDP port and the DERP node advertises it as its STUNPort, so a client's
// netcheck and STUN schedule can be exercised; the hello line carries "stun_port".
//
// Environment: INTEROP_CONTROL_PORT / INTEROP_DERP_PORT pin the two listening ports (so a restarted server is found at the same address; the DERP
// certificate, and with it the advertised pin, is new on every start).
//
// The DERP node is advertised with CertName "sha256-raw:<hex sha256 of the self-signed leaf>" so a client that pins it (the Rust gateway) can trust it.
// The tailnet's MagicDNS domain is "tailnet.test" (node names are "<hostname>.tailnet.test.").
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
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
	dsrv.Listener.Close()
	dsrv.Listener = listenOn("INTEROP_DERP_PORT")
	dsrv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	dsrv.StartTLS()
	var dport int
	fmt.Sscanf(dsrv.Listener.Addr().String()[strings.LastIndex(dsrv.Listener.Addr().String(), ":")+1:], "%d", &dport)

	stunPort := serveSTUN()
	pin := sha256.Sum256(dsrv.Certificate().Raw)
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{900: {
		RegionID: 900, RegionCode: "tst", RegionName: "Test",
		Nodes: []*tailcfg.DERPNode{{Name: "900a", RegionID: 900, HostName: "127.0.0.1", IPv4: "127.0.0.1", DERPPort: dport, STUNPort: stunPort, InsecureForTests: true,
			CertName: "sha256-raw:" + hex.EncodeToString(pin[:])}},
	}}}
	// INTEROP_DERP2=1: a second, unmeshed DERP server as region 901 (a packet sent to one region is not forwarded to a client connected to the other: a peer homed on
	// 901 is reachable only through 901). The `nohome <region>` command marks a region NoMeasureNoHome so that nodes started afterwards cannot choose it as their home.
	var d2port int
	if os.Getenv("INTEROP_DERP2") != "" {
		ds2 := derpserver.New(key.NewNode(), func(f string, a ...any) { log.Printf("derp2: "+f, a...) })
		mux2 := http.NewServeMux()
		mux2.Handle("/derp", derpserver.Handler(ds2))
		mux2.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		dsrv2 := httptest.NewUnstartedServer(mux2)
		dsrv2.Listener.Close()
		dsrv2.Listener = listenOn("INTEROP_DERP2_PORT")
		dsrv2.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
		dsrv2.StartTLS()
		fmt.Sscanf(dsrv2.Listener.Addr().String()[strings.LastIndex(dsrv2.Listener.Addr().String(), ":")+1:], "%d", &d2port)
		pin2 := sha256.Sum256(dsrv2.Certificate().Raw)
		dm.Regions[901] = &tailcfg.DERPRegion{
			RegionID: 901, RegionCode: "tsu", RegionName: "Test 2",
			Nodes: []*tailcfg.DERPNode{{Name: "901a", RegionID: 901, HostName: "127.0.0.1", IPv4: "127.0.0.1", DERPPort: d2port, STUNPort: stunPort, InsecureForTests: true,
				CertName: "sha256-raw:" + hex.EncodeToString(pin2[:])}},
		}
	}
	ctl := &testcontrol.Server{DERPMap: dm, AllOnline: true, Verbose: false, MagicDNSDomain: "tailnet.test"}
	csrv := httptest.NewUnstartedServer(ctl)
	csrv.Listener.Close()
	csrv.Listener = listenOn("INTEROP_CONTROL_PORT")
	csrv.Start()
	ctl.HTTPTestServer = csrv
	defer csrv.Close()

	out := bufio.NewWriter(os.Stdout)
	hello, _ := json.Marshal(map[string]any{"control": ctl.BaseURL(), "derp_host": "127.0.0.1", "derp_port": dport, "derp2_port": d2port, "stun_port": stunPort, "derp_pub": ds.PublicKey().UntypedHexString()})
	fmt.Fprintln(out, string(hello))
	out.Flush()

	peers := map[string]*tsnet.Server{}
	var mu sync.Mutex
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
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
		case "nohome":
			var id int
			if len(f) < 2 {
				fmt.Fprintln(out, "ERR usage")
				break
			}
			fmt.Sscanf(f[1], "%d", &id)
			if r, ok := dm.Regions[tailcfg.DERPRegionID(id)]; ok {
				r.NoMeasureNoHome = true
				fmt.Fprintln(out, "OK")
			} else {
				fmt.Fprintln(out, "ERR no region")
			}
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
		case "ids":
			ns := ctl.AllNodes()
			fmt.Fprint(out, "IDS")
			for _, n := range ns {
				fmt.Fprintf(out, " %s=%d:%s", n.Name, n.ID, n.Key.String())
			}
			fmt.Fprintln(out)
		case "eps":
			var nk key.NodePublic
			if len(f) < 2 || nk.UnmarshalText([]byte(f[1])) != nil {
				fmt.Fprintln(out, "ERR bad key")
				break
			}
			n := ctl.Node(nk)
			if n == nil {
				fmt.Fprintln(out, "ERR no such node")
				break
			}
			var eps []string
			for _, e := range n.Endpoints {
				eps = append(eps, e.String())
			}
			fmt.Fprintf(out, "EPS %s\n", strings.Join(eps, ","))
		case "rawmap":
			var nk key.NodePublic
			if len(f) < 3 || nk.UnmarshalText([]byte(f[1])) != nil {
				fmt.Fprintln(out, "ERR bad key")
				break
			}
			var mr tailcfg.MapResponse
			if err := json.Unmarshal([]byte(strings.Join(f[2:], " ")), &mr); err != nil {
				fmt.Fprintf(out, "ERR json %v\n", err)
				break
			}
			if ctl.AddRawMapResponse(nk, &mr) {
				fmt.Fprintln(out, "OK")
			} else {
				fmt.Fprintln(out, "ERR no such node or queue full")
			}
		case "peerclose":
			mu.Lock()
			p := peers[f[len(f)-1]]
			delete(peers, f[len(f)-1])
			mu.Unlock()
			if p == nil {
				fmt.Fprintln(out, "ERR no such peer")
				break
			}
			p.Close()
			fmt.Fprintln(out, "OK")
		case "peer":
			name := "gopeer"
			if len(f) > 1 {
				name = f[1]
			}
			peer := &tsnet.Server{Hostname: name, ControlURL: ctl.BaseURL(), Ephemeral: true, AuthKey: "tskey-fake", Dir: mustTemp(), Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
			st, err := peer.Up(context.Background())
			if err != nil {
				fmt.Fprintf(out, "ERR %v\n", err)
				break
			}
			serveEcho(peer, name)
			mu.Lock()
			peers[name] = peer
			mu.Unlock()
			fmt.Fprintf(out, "PEER %s %s\n", st.TailscaleIPs[0], st.Self.PublicKey.String())
		case "quit":
			mu.Lock()
			for _, p := range peers {
				p.Close()
			}
			mu.Unlock()
			out.Flush()
			return
		default:
			fmt.Fprintln(out, "ERR unknown")
		}
		out.Flush()
	}
}

// serveSTUN answers STUN binding requests on a loopback UDP port and returns the port.
func serveSTUN() int {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if !stun.Is(buf[:n]) {
				continue
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			ap := from.(*net.UDPAddr).AddrPort()
			pc.WriteTo(stun.Response(tx, ap), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// listenOn listens on 127.0.0.1:$env (an ephemeral port when the variable is unset).
func listenOn(env string) net.Listener {
	addr := "127.0.0.1:0"
	if p := os.Getenv(env); p != "" {
		addr = "127.0.0.1:" + p
	}
	var l net.Listener
	var err error
	for i := 0; i < 50; i++ { // a just-killed predecessor may still hold the port for a moment
		if l, err = net.Listen("tcp", addr); err == nil {
			return l
		}
		time.Sleep(100 * time.Millisecond)
	}
	panic(err)
}

func mustTemp() string {
	d, err := os.MkdirTemp("", "tsnet-gopeer")
	if err != nil {
		panic(err)
	}
	return d
}

// serveEcho starts the services of a peer: TCP echo on :7, a byte sink that reports its count on :9, and HTTP on :80.
func serveEcho(peer *tsnet.Server, name string) {
	if ln, err := peer.Listen("tcp", ":7"); err == nil {
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
	if ln, err := peer.Listen("tcp", ":9"); err == nil {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					n, _ := io.Copy(io.Discard, c)
					fmt.Fprintf(c, "%d\n", n)
				}()
			}
		}()
	}
	if ln, err := peer.Listen("tcp", ":80"); err == nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "hello from %s\n", name) })
		mux.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
			n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/bytes/"))
			if err != nil || n < 0 {
				http.Error(w, "bad count", 400)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(n))
			buf := make([]byte, 16384)
			for i := range buf {
				buf[i] = byte(i * 7)
			}
			for n > 0 {
				k := len(buf)
				if k > n {
					k = n
				}
				if _, err := w.Write(buf[:k]); err != nil {
					return
				}
				n -= k
			}
		})
		go http.Serve(ln, mux)
	}
}
