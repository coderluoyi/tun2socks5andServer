package tcpipnet

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// nicPromiscuousModeEnabled is the value used by stack to enable
	// or disable NIC's promiscuous mode.
	nicPromiscuousModeEnabled = true

	// nicSpoofingEnabled is the value used by stack to enable or disable
	// NIC's spoofing.
	nicSpoofingEnabled = true
)

// creates NIC for stack.
func CreateNICWithOptions(s *stack.Stack, nicID tcpip.NICID, ep stack.LinkEndpoint) error {
	if err := s.CreateNICWithOptions(nicID, ep,
		stack.NICOptions{
			Disabled: false,
			// If no queueing discipline was specified
			// provide a stub implementation that just
			// delegates to the lower link endpoint.
			QDisc: nil,
		}); err != nil {
		return fmt.Errorf("create NIC: %s", err)
	}
	return nil
}

// sets promiscuous mode in the given NICs.
func SetPromiscuousMode(s *stack.Stack, nicID tcpip.NICID, v bool) error {
	if err := s.SetPromiscuousMode(nicID, v); err != nil {
		return fmt.Errorf("set promiscuous mode: %s", err)
	}
	return nil
}

// sets address spoofing in the given NICs, allowing
// endpoints to bind to any address in the NIC.
func SetSpoofing(s *stack.Stack, nicID tcpip.NICID, v bool) error {
	if err := s.SetSpoofing(nicID, v); err != nil {
		return fmt.Errorf("set spoofing: %s", err)
	}
	return nil
}
