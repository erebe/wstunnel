{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE OverloadedStrings   #-}

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

import           Data.Binary               (decode, encode)

import           Logger
import qualified Socks5
import           Types


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
                   , appWrite = \payload -> void $ N.sendAllTo socket payload (N.addrAddress addrInfo)
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
                               , appWrite = \payload' -> void $ N.sendAllTo socket payload' addr
                               }
      void $ atomicModifyIORef' clientsCtx (\clients -> (H.insert addr appData clients, ()))
      return appData

    removeClient :: IORef (H.HashMap N.SockAddr UdpAppData) -> UdpAppData -> IO ()
    removeClient clientsCtx clientCtx = do
      void $ atomicModifyIORef' clientsCtx (\clients -> (H.delete (appAddr clientCtx) clients, ()))
      debug "TIMEOUT connection"

    pushDataToClient :: UdpAppData -> ByteString -> IO ()
    pushDataToClient clientCtx payload = putMVar (appSem clientCtx) payload
      `catch` (\(_ :: SomeException) -> debug $ "DROP udp packet, client thread dead")
     -- If we are unlucky the client's thread died before we had the time to push the data on a already full mutex
     -- and will leave us waiting forever for the mutex to empty. So catch the exeception and drop the message.
     -- Udp is not a reliable protocol so transmission failure should be handled by the application layer

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


runSocks5Server :: Socks5.ServerSettings -> TunnelSettings -> (TunnelSettings -> N.AppData -> IO()) -> IO ()
runSocks5Server socksSettings@Socks5.ServerSettings{..} cfg inner = do
  info $ "Starting socks5 proxy " <> show socksSettings

  N.runTCPServer (N.serverSettingsTCP (fromIntegral listenOn) (fromString bindOn)) $ \cnx -> do
    -- Get the auth request and response with a no Auth
    authRequest <- decode . fromStrict <$> N.appRead cnx :: IO Socks5.ResponseAuth
    debug $ "Socks5 authentification request " <> show authRequest
    let responseAuth = encode $ Socks5.ResponseAuth (fromIntegral Socks5.socksVersion) Socks5.NoAuth
    N.appWrite cnx (toStrict responseAuth)

    -- Get the request and update dynamically the tunnel config
    request <- decode . fromStrict <$> N.appRead cnx :: IO Socks5.Request
    debug $ "Socks5 forward request " <> show request
    let responseRequest =  encode $ Socks5.Response (fromIntegral Socks5.socksVersion) Socks5.SUCCEEDED (Socks5.addr request) (Socks5.port request)
    let cfg' = cfg { destHost = Socks5.addr request, destPort = Socks5.port request }
    N.appWrite cnx (toStrict responseRequest)

    inner cfg' cnx

  info $ "Closing socks5 proxy " <> show socksSettings
