{-|
Module      : Network.NSFW.Firewall.Packet
Description : Defines the Packet data type.
-}
module Network.NSFW.Firewall.Packet where

import Data.Int (Int8, Int16)

type IpAddress = String
type Protocol = String

data Packet = Packet {
  getProtocol             :: Protocol,
  getTtl                  :: Int8,
  getSourceIpAddress      :: IpAddress,
  getSourcePort           :: Int16,
  getDestinationIpAddress :: IpAddress,
  getDestinationPort      :: Int16,
  getDestinationService   :: String
  } deriving (Eq, Read, Show)
