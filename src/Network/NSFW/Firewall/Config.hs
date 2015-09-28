module Network.NSFW.Firewall.Config
       ( Config(..)
       , loadConfig
       , showConfigParseError
       ) where

import Control.Monad.Except (join, liftIO, runExceptT)
import Data.ConfigFile (CPError, emptyCP, get, readfile)
import Data.Default (Default, def)

-- | Configuration data.
data Config = Config {
  getLogLevel :: Int
  } deriving (Eq, Read, Show)

instance Default Config where
  def = Config 0

loadConfig :: IO (Either CPError Config)
loadConfig = runExceptT $ do
  cp <- join $ liftIO $ readfile emptyCP "/etc/nsfw/nsfw.cfg"
  logLevel <- get cp "DEFAULT" "log_level"
  return $ Config logLevel

showConfigParseError :: CPError -> IO ()
showConfigParseError err = do
  putStrLn "Error when parsing NSFW configuration file:"
  putStrLn $ "\t" ++ show err
