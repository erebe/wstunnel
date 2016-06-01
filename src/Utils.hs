{-# LANGUAGE NoImplicitPrelude #-}

module Utils where

import           ClassyPrelude
import           Network.Socket    (HostName, PortNumber)
import qualified System.Log.Logger as LOG


toStr :: (HostName, PortNumber) -> String
toStr (host, port) = fromString host <> ":" <> show port

err :: String -> IO()
err msg = LOG.errorM "wstunnel" $ "ERROR :: " <> msg

info :: String -> IO()
info = LOG.infoM "wstunnel"

debug :: String -> IO()
debug msg = LOG.debugM "wstunnel" $ "DEBUG :: " <> msg
