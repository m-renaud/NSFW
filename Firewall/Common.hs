{-|
Module      : Firewall.Common
Description : Common types and constructor functions.
-}
module Firewall.Common where

import Control.Monad.RWS (RWS)
import Data.IP (IP)
import Firewall.Packet

-- | Configuration data.
data Config = Config {
  getLogLevel :: Int
  } deriving (Eq, Read, Show)

-- | The state shared throughout the FirewallMonad.
data FirewallState = FirewallState {
  getProtocolBlacklist :: [Protocol],
  getSourceIpBlacklist :: [IP]
  } deriving (Eq, Read, Show)

-- | Constructs a FirewallState that automatically converts string IPs to Data.IP.
makeFirewallState :: [Protocol] -> [String] -> FirewallState
makeFirewallState protocolBlacklist sourceIpBlacklist =
  FirewallState protocolBlacklist (map (read :: String -> IP) sourceIpBlacklist)

-- | The level of a log entry.
data LogLevel = LogInfo | LogWarn | LogError
              deriving (Eq, Read, Show)

-- | Defines a structured log entry. Includes the log level and a string message.
data LogEntry = LogEntry {
  logLevel  :: LogLevel,
  message   :: String
  } deriving (Eq)

instance Show LogEntry where
  show (LogEntry l s) = show l ++ " | " ++ s


-- | Defines a firewall rule and the action that should be taken on the packet.
data Action = ACCEPT  -- ^ Accept the packet and perform no further processing.
            | PASS    -- ^ Pass the packet to the next rule in the chain.
            | DROP    -- ^ Drop the packet.
            deriving (Eq, Read, Show)

-- | A firewall rule is a function taking a Packet and operates in the FirewallMonad.
type PacketFilterRule a = Packet -> FirewallMonad a

-- | The monad that the firewall operates in.
type FirewallMonad a = RWS Config [LogEntry] FirewallState a
