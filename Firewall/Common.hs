{-|
Module      : Firewall.Common
Description : Common types and constructor functions.
-}
module Firewall.Common where

import Control.Monad.RWS (RWS)
import Firewall.Packet

-- | Configuration data.
data Config = Config {
  getLogLevel :: Int
  } deriving (Eq, Read, Show)

-- | The state shared throughout the FirewallMonad.
data FirewallState = FirewallState {
  getProtocolBlacklist :: [Protocol],
  getSourceIpBlacklist :: [IpAddress]
  } deriving (Eq, Read, Show)

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

-- | A packet filter rule is a function taking a Packet, operates in the FirewallMonad,
-- and either ACCPETs, PASSes, or DROPs the Packet.
type PacketFilterRule a = Packet -> FirewallMonad a

-- | The monad that the firewall operates in.
-- Has a readable Config, a writable list of log entries, and a modifyable state.
type FirewallMonad a = RWS Config [LogEntry] FirewallState a
