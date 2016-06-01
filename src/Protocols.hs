{-# LANGUAGE DeriveAnyClass      #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE NoImplicitPrelude   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}

module Protocols where

import           ClassyPrelude
import           Control.Concurrent        (forkIO)
import qualified Data.HashMap.Strict       as H
import           System.Timeout            (timeout)

import qualified Data.ByteString.Char8     as BC

import qualified Data.Streaming.Network    as N

import           Network.Socket            (HostName, PortNumber)
import qualified Network.Socket            as N hiding (recv, recvFrom, send,
                                                 sendTo)
import qualified Network.Socket.ByteString as N

import           Utils

deriving instance Generic PortNumber
deriving instance Hashable PortNumber
deriving instance Generic N.SockAddr
deriving instance Hashable N.SockAddr

data Protocol = UDP | TCP deriving (Show, Read)


data UdpAppData = UdpAppData
  { appAddr  :: N.SockAddr
  , appSem   :: MVar ByteString
  , appRead  :: IO ByteString
  , appWrite :: ByteString -> IO ()
  }

instance N.HasReadWrite UdpAppData where
  readLens f appData =  fmap (\getData -> appData { appRead = getData})  (f $ appRead appData)
  writeLens f appData = fmap (\writeData -> appData { appWrite = writeData}) (f $ appWrite appData)


runTCPServer :: (HostName, PortNumber) -> (N.AppData -> IO ()) -> IO ()
runTCPServer endPoint@(host, port) app = do
  info $ "WAIT for tcp connection on " <> toStr endPoint
  void $ N.runTCPServer (N.serverSettingsTCP (fromIntegral port) (fromString host)) app
  info $ "CLOSE tcp server on " <> toStr endPoint

runTCPClient :: (HostName, PortNumber) -> (N.AppData -> IO ()) -> IO ()
runTCPClient endPoint@(host, port) app = do
  info $ "CONNECTING to " <> toStr endPoint
  void $ N.runTCPClient (N.clientSettingsTCP (fromIntegral port) (BC.pack host)) app
  info $ "CLOSE connection to " <> toStr endPoint


runUDPClient :: (HostName, PortNumber) -> (UdpAppData -> IO ()) -> IO ()
runUDPClient endPoint@(host, port) app = do
  info $ "SENDING datagrammes to " <> toStr endPoint
  bracket (N.getSocketUDP host (fromIntegral port)) (N.close . fst) $ \(socket, addrInfo) -> do
    sem <- newEmptyMVar
    app UdpAppData { appAddr  = N.addrAddress addrInfo
                   , appSem   = sem
                   , appRead  = fst <$> N.recvFrom socket 4096
                   , appWrite = \payload -> void $ N.sendTo socket payload (N.addrAddress addrInfo)
                   }

  info $ "CLOSE udp connection to " <> toStr endPoint


runUDPServer :: (HostName, PortNumber) -> (UdpAppData -> IO ()) -> IO ()
runUDPServer endPoint@(host, port) app = do
  info $ "WAIT for datagrames on " <> toStr endPoint
  clientsCtx <- newIORef mempty
  void $ bracket (N.bindPortUDP (fromIntegral port) (fromString host)) N.close (runEventLoop clientsCtx)
  info $ "CLOSE udp server" <> toStr endPoint

  where
    addNewClient :: IORef (H.HashMap N.SockAddr UdpAppData) -> N.Socket -> N.SockAddr -> ByteString -> IO UdpAppData
    addNewClient clientsCtx socket addr payload = do
      sem <- newMVar payload
      let appData = UdpAppData { appAddr  = addr
                               , appSem   = sem
                               , appRead  = takeMVar sem
                               , appWrite = \payload' -> void $ N.sendTo socket payload' addr
                               }
      void $ atomicModifyIORef' clientsCtx (\clients -> (H.insert addr appData clients, ()))
      return appData

    removeClient :: IORef (H.HashMap N.SockAddr UdpAppData) -> UdpAppData -> IO ()
    removeClient clientsCtx clientCtx = do
      void $ atomicModifyIORef' clientsCtx (\clients -> (H.delete (appAddr clientCtx) clients, ()))
      debug "TIMEOUT connection"

    pushDataToClient :: UdpAppData -> ByteString -> IO ()
    pushDataToClient clientCtx = putMVar (appSem clientCtx)

    runEventLoop :: IORef (H.HashMap N.SockAddr UdpAppData) -> N.Socket -> IO ()
    runEventLoop clientsCtx socket = forever $ do
      (payload, addr) <- N.recvFrom socket 4096
      clientCtx <- H.lookup addr <$> readIORef clientsCtx

      case clientCtx of
        Just clientCtx' -> pushDataToClient clientCtx' payload
        _               -> void . forkIO $ bracket
                              (addNewClient clientsCtx socket addr payload)
                              (removeClient clientsCtx)
                              (void . timeout (30 * 10^(6 :: Int)) . app)
