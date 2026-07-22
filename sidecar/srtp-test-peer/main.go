package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
)

func main() {
	role := flag.String("role", "client", "DTLS role: client or server")
	local := flag.String("local", "127.0.0.1:0", "local UDP bind address")
	remote := flag.String("remote", "", "remote media address (the SBC relay's media port)")
	peerFP := flag.String("peer-fp", "", "expected peer (SBC) SDP fingerprint")
	count := flag.Int("count", 50, "number of SRTP packets to send")
	ssrc := flag.Uint("ssrc", 0x1234, "RTP SSRC")
	flag.Parse()

	if *remote == "" || *peerFP == "" {
		fmt.Fprintln(os.Stderr, "peer: -remote and -peer-fp are required")
		os.Exit(2)
	}
	r := dtlssession.RoleClient
	if *role == "server" {
		r = dtlssession.RoleServer
	}

	id, err := dtlssession.GenerateIdentity()
	if err != nil {
		fatal(err)
	}
	// Print our fingerprint first so a harness can provision the far side.
	fmt.Printf("FINGERPRINT %s\n", id.Fingerprint())

	laddr, err := net.ResolveUDPAddr("udp", *local)
	if err != nil {
		fatal(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", *remote)
	if err != nil {
		fatal(err)
	}
	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fatal(err)
	}
	// Publish our bound address so a harness can point the SBC's relay at us.
	fmt.Printf("LOCAL %s\n", sock.LocalAddr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := RunPeer(ctx, r, sock, raddr, id, *peerFP, *count, uint32(*ssrc), 500*time.Millisecond)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("RESULT sent=%d received=%d rtcp_sent=%d rtcp_received=%d profile=%d\n",
		res.Sent, res.Received, res.SentRTCP, res.ReceivedRTCP, res.Profile)
	if res.Received == 0 {
		os.Exit(1) // no media crossed the SBC
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "peer:", err)
	os.Exit(1)
}
