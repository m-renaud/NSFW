{-# LANGUAGE FlexibleContexts #-}
{-|
Module      : Firewall.Logging
Description : Provides utilities for writing logs.

The utility functions handle automatically extracting the log level from the
Config and logging appropriately.
-}
module Firewall.Logging where

import Firewall.Common

import Control.Monad (when)
import Control.Monad.RWS (MonadReader, MonadWriter, ask, tell)

-- | Write a message with the specified to the logs, but only if logging is enabled in the configs.
-- Logging is enabled if logLevel > 0.
-- Works within any monad that can read the Config and write to logs.
logMsg :: (MonadReader Config m, MonadWriter [LogEntry] m) => LogLevel -> String -> m ()
logMsg level s = do
  config <- ask
  when (getLogLevel config > 0) $ tell [LogEntry level s]
