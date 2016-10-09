module Logger where

import           ClassyPrelude
import           Network.Socket    (HostName, PortNumber)
import qualified System.Log.Logger as LOG


data Verbosity = QUIET | VERBOSE | NORMAL

init :: Verbosity -> IO ()
init lvl = LOG.updateGlobalLogger "wstunnel" $ case lvl of
  QUIET   -> LOG.setLevel LOG.ERROR
  VERBOSE -> LOG.setLevel LOG.DEBUG
  NORMAL  -> LOG.setLevel LOG.INFO

toStr :: (HostName, PortNumber) -> String
toStr (host, port) = fromString host <> ":" <> show port

err :: String -> IO()
err msg = LOG.errorM "wstunnel" $ "ERROR :: " <> msg

info :: String -> IO()
info = LOG.infoM "wstunnel"

debug :: String -> IO()
debug msg = LOG.debugM "wstunnel" $ "DEBUG :: " <> msg
