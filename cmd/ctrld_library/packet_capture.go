package ctrld_library

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/cmd/cli"
	"github.com/Control-D-Inc/ctrld/cmd/ctrld_library/netstack"
	"github.com/miekg/dns"
)

// PacketAppCallback extends AppCallback with packet read/write capabilities.
// Mobile platforms implementing full packet capture should use this interface.
type PacketAppCallback interface {
	AppCallback

	// ReadPacket reads a raw IP packet from the TUN interface.
	// This should be a blocking call that returns when a packet is available.
	ReadPacket() ([]byte, error)

	// WritePacket writes a raw IP packet back to the TUN interface.
	WritePacket(packet []byte) error

	// ClosePacketIO closes packet I/O resources.
	ClosePacketIO() error

	// ProtectSocket protects a socket file descriptor from being routed through the VPN.
	// On Android, this calls VpnService.protect() to prevent routing loops.
	// On iOS, this marks the socket to bypass the VPN.
	// Returns nil on success, error on failure.
	ProtectSocket(fd int) error
}

// PacketCaptureController holds state for packet capture mode
type PacketCaptureController struct {
	baseController *Controller

	// Packet capture mode fields
	netstackCtrl *netstack.NetstackController
	dnsBridge    *netstack.DNSBridge
	packetStopCh chan struct{}
}

// NewPacketCaptureController creates a new packet capture controller
func NewPacketCaptureController(appCallback PacketAppCallback) *PacketCaptureController {
	return &PacketCaptureController{
		baseController: &Controller{AppCallback: appCallback},
		packetStopCh:   make(chan struct{}),
	}
}

// StartWithPacketCapture starts ctrld in full packet capture mode for mobile.
// This method enables full IP packet processing with DNS filtering and upstream routing.
// It requires a PacketAppCallback that provides packet read/write capabilities.
func (pc *PacketCaptureController) StartWithPacketCapture(
	packetCallback PacketAppCallback,
	CdUID string,
	ProvisionID string,
	CustomHostname string,
	HomeDir string,
	UpstreamProto string,
	logLevel int,
	logPath string,
) error {
	if pc.baseController.stopCh != nil {
		return fmt.Errorf("controller already running")
	}

	// Set up configuration
	pc.baseController.Config = cli.AppConfig{
		CdUID:          CdUID,
		ProvisionID:    ProvisionID,
		CustomHostname: CustomHostname,
		HomeDir:        HomeDir,
		UpstreamProto:  UpstreamProto,
		Verbose:        logLevel,
		LogPath:        logPath,
	}
	pc.baseController.AppCallback = packetCallback

	// Set global socket protector for HTTP client sockets (API calls, etc)
	// This prevents routing loops when ctrld makes HTTP requests to api.controld.com
	ctrld.SetSocketProtector(packetCallback.ProtectSocket)

	// Create DNS bridge for communication between netstack and DNS proxy
	pc.dnsBridge = netstack.NewDNSBridge()
	pc.dnsBridge.Start()

	// Create packet handler that wraps the mobile callbacks
	packetHandler := netstack.NewMobilePacketHandler(
		packetCallback.ReadPacket,
		packetCallback.WritePacket,
		packetCallback.ClosePacketIO,
		packetCallback.ProtectSocket,
	)

	// Create DNS handler that uses the bridge
	dnsHandler := func(query []byte) ([]byte, error) {
		// Extract source IP from query context if available
		// For now, use a placeholder
		return pc.dnsBridge.ProcessQuery(query, "10.0.0.2", 0)
	}

	// Create netstack configuration
	tunIPv4, err := netip.ParseAddr("10.0.0.1")
	if err != nil {
		return fmt.Errorf("failed to parse TUN IPv4: %v", err)
	}

	netstackCfg := &netstack.Config{
		MTU:               1500,
		TUNIPv4:           tunIPv4,
		DNSHandler:        dnsHandler,
		UpstreamInterface: nil, // Will use default interface
	}

	// Create netstack controller
	netstackCtrl, err := netstack.NewNetstackController(packetHandler, netstackCfg)
	if err != nil {
		pc.dnsBridge.Stop()
		return fmt.Errorf("failed to create netstack controller: %v", err)
	}

	pc.netstackCtrl = netstackCtrl

	// Start netstack processing
	if err := pc.netstackCtrl.Start(); err != nil {
		pc.dnsBridge.Stop()
		return fmt.Errorf("failed to start netstack: %v", err)
	}

	// Start regular ctrld DNS processing in background
	// This allows us to use existing DNS filtering logic
	pc.baseController.stopCh = make(chan struct{})

	// Start DNS query processor that receives queries from the bridge
	// and sends them to the ctrld DNS proxy
	go pc.processDNSQueries()

	// Start the main ctrld mobile runner
	go func() {
		appCallback := mapCallback(pc.baseController.AppCallback)
		cli.RunMobile(&pc.baseController.Config, &appCallback, pc.baseController.stopCh)
	}()

	return nil
}

// processDNSQueries processes DNS queries from the bridge using the ctrld DNS proxy
func (pc *PacketCaptureController) processDNSQueries() {
	queryCh := pc.dnsBridge.GetQueryChannel()

	for {
		select {
		case <-pc.packetStopCh:
			return
		case <-pc.baseController.stopCh:
			return
		case query := <-queryCh:
			go pc.handleDNSQuery(query)
		}
	}
}

// handleDNSQuery handles a single DNS query
func (pc *PacketCaptureController) handleDNSQuery(query *netstack.DNSQuery) {
	// Parse DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(query.Query); err != nil {
		return
	}

	// Send query to actual DNS proxy running on localhost:5354
	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	response, _, err := client.Exchange(msg, "127.0.0.1:5354")
	if err != nil {
		// Create SERVFAIL response
		response = new(dns.Msg)
		response.SetReply(msg)
		response.Rcode = dns.RcodeServerFailure
	}

	// Pack response
	responseBytes, err := response.Pack()
	if err != nil {
		return
	}

	// Send response back through bridge
	pc.dnsBridge.SendResponse(query.ID, responseBytes)
}

// Stop stops the packet capture controller
func (pc *PacketCaptureController) Stop(restart bool, pin int64) int {
	var errorCode = 0

	// Clear global socket protector
	ctrld.SetSocketProtector(nil)

	// Stop DNS bridge
	if pc.dnsBridge != nil {
		pc.dnsBridge.Stop()
		pc.dnsBridge = nil
	}

	// Stop netstack
	if pc.netstackCtrl != nil {
		if err := pc.netstackCtrl.Stop(); err != nil {
			// Log error but continue shutdown
			fmt.Printf("Error stopping netstack: %v\n", err)
		}
		pc.netstackCtrl = nil
	}

	// Close packet stop channel
	if pc.packetStopCh != nil {
		close(pc.packetStopCh)
		pc.packetStopCh = make(chan struct{})
	}

	// Stop base controller
	if !restart {
		errorCode = cli.CheckDeactivationPin(pin, pc.baseController.stopCh)
	}
	if errorCode == 0 && pc.baseController.stopCh != nil {
		close(pc.baseController.stopCh)
		pc.baseController.stopCh = nil
	}

	return errorCode
}

// IsRunning returns true if the controller is running
func (pc *PacketCaptureController) IsRunning() bool {
	return pc.baseController.stopCh != nil
}

// IsPacketMode returns true (always in packet mode for this controller)
func (pc *PacketCaptureController) IsPacketMode() bool {
	return true
}
