{-# LANGUAGE BangPatterns         #-}
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
import           Control.Concurrent.Async  (async, race_)
import qualified Data.HashMap.Strict       as H
import           System.Timeout            (timeout)

import qualified Data.ByteString           as B
import qualified Data.ByteString.Char8     as BC

import qualified Data.Streaming.Network    as N
import           Network.Socket            (HostName, PortNumber)
import qualified Network.Socket            as N hiding (recv, recvFrom, send,
                                                 sendTo)
import qualified Network.Socket.ByteString as N

import qualified Network.WebSockets        as WS
import qualified Network.WebSockets.Stream as WS

import           Network.Connection        (Connection, ConnectionParams (..),
                                            TLSSettings (..), connectTo,
                                            connectionGetChunk, connectionPut,
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
  bracket
    (N.getSocketUDP host (fromIntegral port))
    (N.close . fst)
    (\(socket, addrInfo) -> do
      sem <- newEmptyMVar
      app UdpAppData { appAddr = N.addrAddress addrInfo
                      , appSem = sem
                      , appRead = fst <$> N.recvFrom socket 4096
                      , appWrite = \payload -> void $ N.sendTo socket payload (N.addrAddress addrInfo)
                      })

  putStrLn $ "CLOSE connection to " <> tshow host <> ":" <> tshow port

runUDPServer :: (HostName, PortNumber) -> (UdpAppData -> IO ()) -> IO ()
runUDPServer (host, port) app = do
  putStrLn $ "WAIT for datagrames on " <> tshow host <> ":" <> tshow port
  notebook <- newMVar mempty
  bracket (N.bindPortUDP (fromIntegral port) (fromString host)) N.close (runEventLoop notebook)
  putStrLn "CLOSE tunnel"

  where
    runEventLoop :: MVar (H.HashMap N.SockAddr UdpAppData) -> N.Socket -> IO ()
    runEventLoop clientMapM socket = do
      (payload, addr) <- N.recvFrom socket 4096
      clientMap <- readMVar clientMapM
      case H.lookup addr clientMap of
        Just appData -> putMVar (appSem appData) payload
        Nothing      -> do
          let action = bracket (do sem <- newMVar payload
                                   let appData = UdpAppData addr sem (takeMVar sem) (\payload' -> void $ N.sendTo socket payload' addr)
                                   void $ swapMVar clientMapM (H.insert addr appData clientMap)
                                   return appData
                               )
                               (\appData' -> do
                                    m <- takeMVar clientMapM
                                    putMVar clientMapM (H.delete (appAddr appData') m)
                                    putStrLn "TIMEOUT connection"
                               )
                               (timeout (30 * 10^(6 :: Int)) . app)

          void $ async action

      runEventLoop clientMapM socket


runTunnelingClient :: Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (WS.Connection -> IO ()) -> IO ()
runTunnelingClient proto (wsHost, wsPort) (remoteHost, remotePort) app = do
  putStrLn $ "OPEN connection to " <> tshow remoteHost <> ":" <> tshow remotePort
  void $  WS.runClient wsHost (fromIntegral wsPort) (toPath proto remoteHost remotePort) app
  putStrLn $ "CLOSE connection to " <> tshow remoteHost <> ":" <> tshow remotePort


runTunnelingServer :: (HostName, PortNumber) -> IO ()
runTunnelingServer (host, port) = do
  putStrLn $ "WAIT for connection on " <> tshow host <> ":" <> tshow port
  WS.runServer host (fromIntegral port) $ \pendingConn -> do
    let path = parsePath . WS.requestPath $ WS.pendingRequest pendingConn
    case path of
      Nothing -> putStrLn "Rejecting connection" >> WS.rejectRequest pendingConn "Invalid tunneling information"
      Just (!proto, !rhost, !rport) -> do
        conn <- WS.acceptRequest pendingConn
        case proto of
          UDP -> runUDPClient (BC.unpack rhost, fromIntegral rport) (propagateRW conn)
          TCP -> runTCPClient (BC.unpack rhost, fromIntegral rport) (propagateRW conn)

  putStrLn "CLOSE server"

  where
    parsePath :: ByteString -> Maybe (Proto, ByteString, Int)
    parsePath path = let rets = BC.split '/' . BC.drop 1 $ path
      in do
        guard (length rets == 3)
        let [protocol, h, prt] = rets
        prt' <- readMay . BC.unpack $ prt :: Maybe Int
        proto <- readMay . toUpper . BC.unpack $ protocol :: Maybe Proto
        return (proto, h, prt')


propagateRW :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateRW hTunnel hOther =
  void $ tryAny $ finally (race_ (propagateReads hTunnel hOther) (propagateWrites hTunnel hOther))
                          (WS.sendClose hTunnel B.empty)

propagateReads :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateReads hTunnel hOther = void . tryAny . forever $ WS.receiveData hTunnel >>= N.appWrite hOther

propagateWrites :: N.HasReadWrite a => WS.Connection -> a -> IO ()
propagateWrites hTunnel hOther = void . tryAny $ do
  payload <- N.appRead hOther
  unless (null payload) (WS.sendBinaryData hTunnel payload >> propagateWrites hTunnel hOther)


runClient :: Bool -> Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (HostName, PortNumber) -> IO ()
runClient useTls proto local wsServer remote = do
  let out = (if useTls then runTlsTunnelingClient else runTunnelingClient) proto wsServer remote
  case proto of
        UDP -> runUDPServer local (\hOther -> out (`propagateRW` hOther))
        TCP -> runTCPServer local (\hOther -> out (`propagateRW` hOther))


runServer :: (HostName, PortNumber) -> IO ()
runServer = runTunnelingServer


runTlsTunnelingClient :: Proto -> (HostName, PortNumber) -> (HostName, PortNumber) -> (WS.Connection -> IO ()) -> IO ()
runTlsTunnelingClient proto (wsHost, wsPort) (remoteHost, remotePort) app = do
  context <- initConnectionContext
  connection <- connectTo context (connectionParams wsHost (fromIntegral wsPort))
  stream <- WS.makeStream (reader connection) (writer connection)
  WS.runClientWithStream stream wsHost (toPath proto remoteHost remotePort) WS.defaultConnectionOptions [] app


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
