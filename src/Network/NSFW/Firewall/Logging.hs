{-# LANGUAGE FlexibleContexts #-}
{-|
Module      : Network.NSFW.Firewall.Logging
Description : Provides utilities for writing logs.

The utility functions handle automatically extracting the log level from the
Config and logging appropriately.
-}
module Network.NSFW.Firewall.Logging where

import Network.NSFW.Firewall.Common (LogEntry(..), LogLevel, FirewallMonad(..))
import Network.NSFW.Firewall.Config

import Control.Monad (when)
import Control.Monad.RWS (ask, tell)

-- | Write a message with the specified to the logs, but only if logging is enabled in the configs.
-- Logging is enabled if logLevel > 0.
logMsg :: LogLevel -> String -> FirewallMonad ()
logMsg level s = do
  config <- ask
  when (getLogLevel config > 0) $ tell [LogEntry level s]
