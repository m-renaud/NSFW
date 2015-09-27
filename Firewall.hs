module Firewall where

import Control.Monad.RWS (runRWS)

import Firewall.Common
import Firewall.Config
import Firewall.Packet
import Firewall.Rule


-- | Simple interactive main where you can enter a string that corresponds to
--   one of the |packets| below and it will run the filters on it.
main :: IO ()
main = do
  maybeConfig <- loadConfig
  case maybeConfig of
   Left err -> showConfigParseError err
   Right config -> readAndFilterForever config defaultState

readAndFilterForever :: Config -> FirewallState -> IO ()
readAndFilterForever config state = do
  packet <- getLine
  case lookup packet packets of
   Nothing -> putStrLn "No known packet"
   Just p  -> do
     let (results, state', logs) = applyRules config state p
     putStrLn $ "Results: " ++ show results
     putStrLn $ "Logs:    " ++ show logs
     readAndFilterForever config state'


-- | The blacklist filters to use when inspecting a packet.
blacklistFilters :: [PacketFilterRule Action]
blacklistFilters = [protocolBlacklistFilter, sourceIpBlacklistFilter]

-- | The set of all packet filters to send a packet through.
packetFilters :: [PacketFilterRule Action]
packetFilters = concat $ [blacklistFilters]

-- | Apply the rules in packetFilters given a config, a state, and a packet.
applyRules :: Config -> FirewallState -> Packet -> ([Action], FirewallState, [LogEntry])
applyRules config state packet = runRWS (sequence filters) config state
  where filters = map ($ packet) packetFilters

packets :: [(String, Packet)]
packets = [("good", goodPacket),
           ("badProtocol", badProtocolPacket),
           ("badSourceIp", badSourceIpPacket)]

-- | Constants so I don't have to type them in everytime I reload
goodPacket, badProtocolPacket, badSourceIpPacket :: Packet
goodPacket        = Packet "ssh"  64 "3.3.3.3" 7000 "2.2.2.2" 80 "ssh"
badProtocolPacket = Packet "http" 64 "9.9.9.9" 7000 "2.2.2.2" 80 "web"
badSourceIpPacket = Packet "ssh"  64 "1.1.1.1" 7000 "2.2.2.2" 80 "web"

noLogging, withLogging :: Config
noLogging   = Config 0
withLogging = Config 1

defaultState :: FirewallState
defaultState = FirewallState ["http"] ["1.1.1.1"]
