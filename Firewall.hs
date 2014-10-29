module Firewall where

import Control.Monad.RWS (runRWS)

import Firewall.Common
import Firewall.Packet
import Firewall.Rule

-- | The blacklist filters to use when inspecting a packet.
blacklistFilters :: [PacketFilterRule Action]
blacklistFilters = [protocolBlacklistFilter, sourceIpBlacklistFilter]

-- | The set of all packet filters to send a packet through.
packetFilters :: [PacketFilterRule Action]
packetFilters = concat $ [blacklistFilters]

-- | Apply the rules in blacklistFilter given a config, a state, and a packet.
applyRules :: Config -> FirewallState -> Packet -> ([Action], FirewallState, [LogEntry])
applyRules config state packet = runRWS (sequence filters) config state
  where filters = map ($ packet) blacklistFilters

-- | Constants so I don't have to type them in everytime I reload
goodPacket        = makePacket "ssh"  64 "3.3.3.3" 7000 "2.2.2.2" 80 "ssh"
badProtocolPacket = makePacket "http" 64 "9.9.9.9" 7000 "2.2.2.2" 80 "web"
badSourceIpPacket = makePacket "ssh"  64 "1.1.1.1" 7000 "2.2.2.2" 80 "web"
noLogging   = Config 0
withLogging = Config 1
blacklists = makeFirewallState ["http"] ["1.1.1.1"]
