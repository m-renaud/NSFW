{-|
Module      : Firewall.Rule
Description : Defines the basic packet filtering rules.
-}
module Firewall.Rule where

import Firewall.Common
import Firewall.Logging
import Firewall.Packet

import Control.Monad.RWS (get)

-- | Function to generate blacklist packet filtering rules.
makeBlacklistFilter :: (Eq a, Show a) =>
                       String -> (Packet -> a) -> (FirewallState -> [a]) -> PacketFilterRule Action
makeBlacklistFilter name getField blacklist packet = do
  fwState <- get
  let field = getField packet
  if field `elem` blacklist fwState
    then do logMsg LogInfo ("Dropping packet because " ++ name ++ " " ++ show field
                            ++ " is blacklisted.")
            return DROP
    else return PASS

-- | Filter a packet by the protocol blacklist in FirewallState.
protocolBlacklistFilter :: PacketFilterRule Action
protocolBlacklistFilter = makeBlacklistFilter "protocol" getProtocol getProtocolBlacklist

-- | Filter a packet by the source IP blacklist in FirewallState.
sourceIpBlacklistFilter :: PacketFilterRule Action
sourceIpBlacklistFilter = makeBlacklistFilter "source IP" getSourceIpAddress getSourceIpBlacklist
