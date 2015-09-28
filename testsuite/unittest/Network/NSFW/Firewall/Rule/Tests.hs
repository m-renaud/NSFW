{-# OPTIONS_GHC -F -pgmF htfpp #-}

module Network.NSFW.Firewall.Rule.Tests
       ( htf_thisModulesTests
       ) where

import Network.NSFW.Firewall.Common
import Network.NSFW.Firewall.Config
import Network.NSFW.Firewall.Packet
import Network.NSFW.Firewall.Rule

import Control.Monad.RWS (runRWS)
import Data.Default (def)
import Test.Framework

test_protocolBlacklist_Drop =
  assertEqual DROP actions
  where (actions, _, _) = runRWS (protocolBlacklistFilter blacklistedPacket)
                          (def :: Config)
                          FirewallState { getProtocolBlacklist = ["http"]
                                        , getSourceIpBlacklist = []
                                        }
        blacklistedPacket = Packet "http" 64 "9.9.9.9" 7000 "2.2.2.2" 80 "web"

test_protocolBlacklist_Pass =
  assertEqual PASS actions
  where (actions, _, _) = runRWS (protocolBlacklistFilter allowedPacket)
                          (def :: Config)
                          FirewallState { getProtocolBlacklist = ["http"]
                                        , getSourceIpBlacklist = []
                                        }
        allowedPacket = Packet "ssh" 64 "9.9.9.9" 7000 "2.2.2.2" 80 "web"

test_sourceIpBlacklist_Drop =
  assertEqual DROP actions
  where (actions, _, _) = runRWS (sourceIpBlacklistFilter blacklistedPacket)
                          (def :: Config)
                          FirewallState { getProtocolBlacklist = []
                                        , getSourceIpBlacklist = ["1.1.1.1"]
                                        }
        blacklistedPacket = Packet "http" 64 "1.1.1.1" 7000 "2.2.2.2" 80 "web"

test_sourceIpBlacklist_Pass =
  assertEqual PASS actions
  where (actions, _, _) = runRWS (sourceIpBlacklistFilter allowedPacket)
                          (def :: Config)
                          FirewallState { getProtocolBlacklist = []
                                        , getSourceIpBlacklist = ["1.1.1.1"]
                                        }
        allowedPacket = Packet "ssh" 64 "9.9.9.9" 7000 "2.2.2.2" 80 "web"
