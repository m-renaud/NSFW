{-|
Module      : Firewall.Packet
Description : Defines the Packet data type.
-}
module Firewall.Packet where

import Data.IP (IP)
import Data.Int (Int8, Int16)

type Protocol = String

data Packet = Packet {
  getProtocol             :: Protocol,
  getTtl                  :: Int8,
  getSourceIpAddress      :: IP,
  getSourcePort           :: Int16,
  getDestinationIpAddress :: IP,
  getDestinationPort      :: Int16,
  getDestinationService   :: String
  } deriving (Eq, Read, Show)

-- | Construct a Packet, automatically converting String IPs to Data.IP.
makePacket :: Protocol -> Int8 -> String -> Int16 -> String -> Int16 -> String -> Packet
makePacket protocol ttl sourceIp sourcePort destinationIp destinationPort service =
  Packet protocol ttl (read sourceIp :: IP) sourcePort (read destinationIp :: IP) destinationPort service
