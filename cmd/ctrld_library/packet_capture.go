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
}

// PacketCaptureController holds state for packet capture mode
type PacketCaptureController struct {
	baseController *Controller

	// Packet capture mode fields
	netstackCtrl    *netstack.NetstackController
	dnsBridge       *netstack.DNSBridge
	packetStopCh    chan struct{}
	dnsProxyAddress string
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
	tunAddress string,
	deviceAddress string,
	mtu int64,
	dnsProxyAddress string,
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

	// Store DNS proxy address for handleDNSQuery
	pc.dnsProxyAddress = dnsProxyAddress

	// Set defaults
	if mtu == 0 {
		mtu = 1500
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

	// Create DNS bridge for communication between netstack and DNS proxy
	pc.dnsBridge = netstack.NewDNSBridge()
	pc.dnsBridge.Start()

	// Create packet handler that wraps the mobile callbacks
	packetHandler := netstack.NewMobilePacketHandler(
		packetCallback.ReadPacket,
		packetCallback.WritePacket,
		packetCallback.ClosePacketIO,
	)

	// Create DNS handler that uses the bridge
	dnsHandler := func(query []byte) ([]byte, error) {
		// Use device address as the source of DNS queries
		return pc.dnsBridge.ProcessQuery(query, deviceAddress, 0)
	}

	// Parse TUN IP address
	tunIPv4, err := netip.ParseAddr(tunAddress)
	if err != nil {
		return fmt.Errorf("failed to parse TUN IPv4 address '%s': %v", tunAddress, err)
	}

	netstackCfg := &netstack.Config{
		MTU:               uint32(mtu),
		TUNIPv4:           tunIPv4,
		DNSHandler:        dnsHandler,
		UpstreamInterface: nil, // Will use default interface
	}

	ctrld.ProxyLogger.Load().Info().Msgf("[PacketCapture] Network config - TUN: %s, Device: %s, MTU: %d, DNS Proxy: %s",
		tunAddress, deviceAddress, mtu, dnsProxyAddress)

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

	// BLOCK here until stopped (critical - Swift expects this to block!)
	ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Blocking until stop signal...")
	<-pc.baseController.stopCh
	ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop signal received, exiting")

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

	// Send query to actual DNS proxy using configured address
	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	response, _, err := client.Exchange(msg, pc.dnsProxyAddress)
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
	ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() called - starting shutdown")
	var errorCode = 0

	// Stop DNS bridge
	if pc.dnsBridge != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - stopping DNS bridge")
		pc.dnsBridge.Stop()
		pc.dnsBridge = nil
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - DNS bridge stopped")
	}

	// Stop netstack
	if pc.netstackCtrl != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - stopping netstack controller")
		if err := pc.netstackCtrl.Stop(); err != nil {
			// Log error but continue shutdown
			ctrld.ProxyLogger.Load().Error().Msgf("[PacketCapture] Stop() - error stopping netstack: %v", err)
		}
		pc.netstackCtrl = nil
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - netstack controller stopped")
	}

	// Close packet stop channel
	if pc.packetStopCh != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - closing packet stop channel")
		select {
		case <-pc.packetStopCh:
			// Already closed
			ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - packet stop channel already closed")
		default:
			close(pc.packetStopCh)
			ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - packet stop channel closed")
		}
		pc.packetStopCh = make(chan struct{})
	}

	// Stop base controller
	ctrld.ProxyLogger.Load().Info().Msgf("[PacketCapture] Stop() - stopping base controller (restart=%v, pin=%d)", restart, pin)
	if !restart {
		errorCode = cli.CheckDeactivationPin(pin, pc.baseController.stopCh)
		ctrld.ProxyLogger.Load().Info().Msgf("[PacketCapture] Stop() - deactivation pin check returned: %d", errorCode)
	}
	if errorCode == 0 && pc.baseController.stopCh != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - closing base controller stop channel")
		select {
		case <-pc.baseController.stopCh:
			// Already closed
			ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - base controller stop channel already closed")
		default:
			close(pc.baseController.stopCh)
			ctrld.ProxyLogger.Load().Info().Msg("[PacketCapture] Stop() - base controller stop channel closed")
		}
		pc.baseController.stopCh = nil
	}

	ctrld.ProxyLogger.Load().Info().Msgf("[PacketCapture] Stop() - shutdown complete, errorCode=%d", errorCode)
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
