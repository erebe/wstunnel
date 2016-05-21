{-# LANGUAGE BangPatterns         #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Lib
    ( runClient
    , runServer
    , Proto (..)
    ) where

import           ClassyPrelude
import           Control.Concurrent.Async      (async, race_)
import qualified Data.HashMap.Strict           as H
import           Data.Maybe                    (fromJust)
import           System.Timeout                (timeout)

import qualified Data.ByteString.Char8         as BC

import qualified Data.Conduit.Network.TLS      as N
import qualified Data.Streaming.Network        as N

import           Network.Socket                (HostName, PortNumber)
import qualified Network.Socket                as N hiding (recv, recvFrom,
                                                     send, sendTo)
import qualified Network.Socket.ByteString     as N

import qualified Network.WebSockets            as WS
import qualified Network.WebSockets.Connection as WS
import qualified Network.WebSockets.Stream     as WS

import           Network.Connection            (Connection,
                                                ConnectionParams (..),
                                                TLSSettings (..), connectTo,
                                                connectionGetChunk,
                                                connectionPut,
                                                initConnectionContext)


instance Hashable N.SockAddr where
  hashWithSalt salt (N.SockAddrInet port host)               = hashWithSalt salt ((fromIntegral port :: Int) + hash host)
  hashWithSalt salt (N.SockAddrInet6 port flow host scopeID) = hashWithSalt salt ((fromIntegral port :: Int) + hash host + hash flow + hash scopeID)
  hashWithSalt salt (N.SockAddrUnix addr)                    = hashWithSalt salt addr
  hashWithSalt salt (N.SockAddrCan addr)                     = hashWithSalt salt addr

data Proto = UDP | TCP deriving (Show, Read)

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
runTCPServer (host, port) app = do
  putStrLn $ "WAIT for connection on " <> tshow host <> ":" <> tshow port
  void $ N.runTCPServer (N.serverSettingsTCP (fromIntegral port) (fromString host)) app
  putStrLn "CLOSE tunnel"

runTCPClient :: (HostName, PortNumber) -> (N.AppData -> IO ()) -> IO ()
runTCPClient (host, port) app = do
  putStrLn $ "CONNECTING to " <> tshow host <> ":" <> tshow port
  void $ N.runTCPClient (N.clientSettingsTCP (fromIntegral port) (BC.pack host)) app
  putStrLn $ "CLOSE connection to " <> tshow host <> ":" <> tshow port


runUDPClient :: (HostName, PortNumber) -> (UdpAppData -> IO ()) -> IO ()
runUDPClient (host, port) app = do
  putStrLn $ "CONNECTING to " <> tshow host <> ":" <> tshow port
  bracket (N.getSocketUDP host (fromIntegral port)) (N.close . fst) $ \(socket, addrInfo) -> do
    sem <- newEmptyMVar
    app UdpAppData { appAddr  = N.addrAddress addrInfo
                   , appSem   = sem
                   , appRead  = fst <$> N.recvFrom socket 4096
                   , appWrite = \payload -> void $ N.sendTo socket payload (N.addrAddress addrInfo)
                   }

  putStrLn $ "CLOSE connection to " <> tshow host <> ":" <> tshow port

runUDPServer :: (HostName, PortNumber) -> (UdpAppData -> IO ()) -> IO ()
runUDPServer (host, port) app = do
  putStrLn $ "WAIT for datagrames on " <> tshow host <> ":" <> tshow port
  clientsCtx <- newIORef mempty
  void $ bracket (N.bindPortUDP (fromIntegral port) (fromString host)) N.close (runEventLoop clientsCtx)
  putStrLn "CLOSE tunnel"

  where
    addNewClient :: IORef (H.HashMap N.SockAddr UdpAppData) -> N.Socket -> N.SockAddr -> ByteString
                    -> IO UdpAppData
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
      putStrLn "TIMEOUT connection"

    pushDataToClient :: UdpAppData -> ByteString -> IO ()
    pushDataToClient clientCtx = putMVar (appSem clientCtx)

    runEventLoop :: IORef (H.HashMap N.SockAddr UdpAppData) -> N.Socket -> IO ()
    runEventLoop clientsCtx socket = forever $ do
      (payload, addr) <- N.recvFrom socket 4096
      clientCtx <- H.lookup addr <$> readIORef clientsCtx

      case clientCtx of
        Just clientCtx' -> pushDataToClient clientCtx' payload
        _               -> void . async $ bracket
                              (addNewClient clientsCtx socket addr payload)
                              (removeClient clientsCtx)
                              (timeout (30 * 10^(6 :: Int)) . app)


runTunnelingClient :: Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (WS.Connection -> IO ()) -> IO ()
runTunnelingClient proto (wsHost, wsPort) (remoteHost, remotePort) app = do
  putStrLn $ "OPEN connection to " <> tshow remoteHost <> ":" <> tshow remotePort
  void $  WS.runClient wsHost (fromIntegral wsPort) (toPath proto remoteHost remotePort) app
  putStrLn $ "CLOSE connection to " <> tshow remoteHost <> ":" <> tshow remotePort


runTlsTunnelingServer :: (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runTlsTunnelingServer (bindTo, portNumber) isAllowed = do
  putStrLn $ "WAIT for TLS connection on " <> tshow bindTo <> ":" <> tshow portNumber
  N.runTCPServerTLS (N.tlsConfigBS (fromString bindTo) (fromIntegral portNumber) serverCertificate serverKey) $ \sClient ->
    runApp sClient WS.defaultConnectionOptions (runServerEventLoop isAllowed)

  putStrLn "CLOSE server"

  where
    runApp :: N.AppData -> WS.ConnectionOptions -> WS.ServerApp -> IO ()
    runApp appData opts  app= do
      stream <- WS.makeStream (Just <$> N.appRead appData) (N.appWrite appData . toStrict . fromJust)
      bracket (WS.makePendingConnectionFromStream stream opts)
              (\conn -> catch (WS.close $ WS.pendingStream conn) (\(_ :: SomeException) -> return ()))
              app

runTunnelingServer :: (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runTunnelingServer (host, port) isAllowed = do
  putStrLn $ "WAIT for connection on " <> tshow host <> ":" <> tshow port

  void $ N.runTCPServer (N.serverSettingsTCP (fromIntegral port) (fromString host)) $ \sClient ->
    runApp (fromJust $ N.appRawSocket sClient) WS.defaultConnectionOptions (runServerEventLoop isAllowed)

  putStrLn "CLOSE server"

  where
    runApp :: N.Socket -> WS.ConnectionOptions -> WS.ServerApp -> IO ()
    runApp socket opts = bracket (WS.makePendingConnection socket opts)
                         (\conn -> catch (WS.close $ WS.pendingStream conn) (\(_ :: SomeException) -> return ()))

runServerEventLoop :: ((ByteString, Int) -> Bool) -> WS.PendingConnection -> IO ()
runServerEventLoop isAllowed pendingConn = do
  let path =  fromPath . WS.requestPath $ WS.pendingRequest pendingConn
  case path of
    Nothing -> putStrLn "Rejecting connection" >> WS.rejectRequest pendingConn "Invalid tunneling information"
    Just (!proto, !rhost, !rport) ->
      if not $ isAllowed (rhost, rport)
      then do
        putStrLn "Rejecting tunneling"
        WS.rejectRequest pendingConn "Restriction is on, You cannot request this tunneling"
      else do
        conn <- WS.acceptRequest pendingConn
        case proto of
          UDP -> runUDPClient (BC.unpack rhost, fromIntegral rport) (propagateRW conn)
          TCP -> runTCPClient (BC.unpack rhost, fromIntegral rport) (propagateRW conn)




propagateRW :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateRW hTunnel hOther =
  myTry $ race_ (propagateReads hTunnel hOther) (propagateWrites hTunnel hOther)

myTry :: IO () -> IO ()
myTry f = void $ catch f (\(_ :: SomeException) -> return ())

propagateReads :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateReads hTunnel hOther = myTry (forever $ WS.receiveData hTunnel >>= N.appWrite hOther)

propagateWrites :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateWrites hTunnel hOther = myTry $ do
  payload <- N.appRead hOther
  unless (null payload) (WS.sendBinaryData hTunnel payload >> propagateWrites hTunnel hOther)


runClient :: Bool -> Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (HostName, PortNumber) -> IO ()
runClient useTls proto local wsServer remote = do
  let out = (if useTls then runTlsTunnelingClient else runTunnelingClient) proto wsServer remote
  case proto of
        UDP -> runUDPServer local (\hOther -> out (`propagateRW` hOther))
        TCP -> runTCPServer local (\hOther -> out (`propagateRW` hOther))


runServer :: Bool -> (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runServer useTLS = if useTLS then runTlsTunnelingServer else runTunnelingServer


runTlsTunnelingClient :: Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (WS.Connection -> IO ()) -> IO ()
runTlsTunnelingClient proto (wsHost, wsPort) (remoteHost, remotePort) app = do
  putStrLn $ "OPEN tls connection to " <> tshow remoteHost <> ":" <> tshow remotePort
  context    <- initConnectionContext
  connection <- connectTo context (connectionParams wsHost (fromIntegral wsPort))
  stream     <- WS.makeStream (reader connection) (writer connection)
  WS.runClientWithStream stream wsHost (toPath proto remoteHost remotePort) WS.defaultConnectionOptions [] app
  putStrLn $ "CLOSE tls connection to " <> tshow remoteHost <> ":" <> tshow remotePort


connectionParams :: HostName -> PortNumber -> ConnectionParams
connectionParams host port = ConnectionParams
  { connectionHostname = host
  , connectionPort = port
  , connectionUseSecure = Just tlsSettings
  , connectionUseSocks = Nothing
  }

tlsSettings :: TLSSettings
tlsSettings = TLSSettingsSimple
  { settingDisableCertificateValidation = True
  , settingDisableSession = False
  , settingUseServerName = False
  }

reader :: Connection -> IO (Maybe ByteString)
reader connection = fmap Just (connectionGetChunk connection)

writer :: Connection -> Maybe LByteString -> IO ()
writer connection = maybe (return ()) (connectionPut connection . toStrict)


toPath :: Proto -> HostName -> PortNumber -> String
toPath proto remoteHost remotePort = "/" <> toLower (show proto) <> "/" <> remoteHost <> "/" <> show remotePort

fromPath :: ByteString -> Maybe (Proto, ByteString, Int)
fromPath path = let rets = BC.split '/' . BC.drop 1 $ path
  in do
    guard (length rets == 3)
    let [protocol, h, prt] = rets
    prt' <- readMay . BC.unpack $ prt :: Maybe Int
    proto <- readMay . toUpper . BC.unpack $ protocol :: Maybe Proto
    return (proto, h, prt')



serverKey :: ByteString
serverKey = "-----BEGIN RSA PRIVATE KEY-----\n" <>
  "MIIBOgIBAAJBAMEEloIcF3sTGYhQmybyDm1NOpXmf94rR1fOwENjuW6jh4WTaz5k\n" <>
  "Uew8CR58e7c5GgK08ZOJwi2Hpl9MfDm4mGUCAwEAAQJAGP+nHqLUx7PpkqYd8iVX\n" <>
  "iQB/nfqEhRnF27GDZTb9RT7e3bR7X1B9oIBnpmqwMG5oPxidoIKv+jzZjsQcxKLu\n" <>
  "4QIhAPdcPmFrtLUpTXx21wtVxotsO7+YcQxtRtBoXeiREUInAiEAx8Jx9a6eVRIh\n" <>
  "slSTJMPuy/LbvK8VUTqtx9x2EhFhBJMCIQC68qlmwZs6y/N3HO4b8AD1gKCLhm/y\n" <>
  "P2ikvCw1R+ZuQwIgdfcgMUPzgK16dMN5OabzaEF8/kouvo92fKZ2m2jj8D0CIFY8\n" <>
  "4SkXDkpeUEKKfxHqrEkkxmpRk93Ui1NPyN+wxrgO\n" <>
  "-----END RSA PRIVATE KEY-----"

serverCertificate :: ByteString
serverCertificate = "-----BEGIN CERTIFICATE-----\n" <>
  "MIICXTCCAgegAwIBAgIJAJf1Sm7DI0KcMA0GCSqGSIb3DQEBBQUAMIGJMQswCQYD\n" <>
  "VQQGEwJGUjESMBAGA1UECAwJQXF1aXRhaW5lMRAwDgYDVQQHDAdCYXlvbm5lMQ4w\n" <>
  "DAYDVQQKDAVFcmViZTELMAkGA1UECwwCSVQxFjAUBgNVBAMMDXJvbWFpbi5nZXJh\n" <>
  "cmQxHzAdBgkqhkiG9w0BCQEWEHdoeW5vdEBnbWFpbC5jb20wHhcNMTYwNTIxMTUy\n" <>
  "MzIyWhcNNDMxMDA2MTUyMzIyWjCBiTELMAkGA1UEBhMCRlIxEjAQBgNVBAgMCUFx\n" <>
  "dWl0YWluZTEQMA4GA1UEBwwHQmF5b25uZTEOMAwGA1UECgwFRXJlYmUxCzAJBgNV\n" <>
  "BAsMAklUMRYwFAYDVQQDDA1yb21haW4uZ2VyYXJkMR8wHQYJKoZIhvcNAQkBFhB3\n" <>
  "aHlub3RAZ21haWwuY29tMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMEEloIcF3sT\n" <>
  "GYhQmybyDm1NOpXmf94rR1fOwENjuW6jh4WTaz5kUew8CR58e7c5GgK08ZOJwi2H\n" <>
  "pl9MfDm4mGUCAwEAAaNQME4wHQYDVR0OBBYEFLY0HsQst1t3QRXU0aTWg3V1IvGX\n" <>
  "MB8GA1UdIwQYMBaAFLY0HsQst1t3QRXU0aTWg3V1IvGXMAwGA1UdEwQFMAMBAf8w\n" <>
  "DQYJKoZIhvcNAQEFBQADQQCP4oYOIrX7xvmQih3hvF4kUnbKjtttImdGruonsLAz\n" <>
  "OL2VExC6OqlDP2yu14BlsjTt+X2v6mhHnSM16c6AkpM/\n" <>
  "-----END CERTIFICATE-----"
