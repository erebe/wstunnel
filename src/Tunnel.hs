{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE NoImplicitPrelude   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}


module Tunnel
    ( runClient
    , runServer
    , TunnelSettings(..)
    , Protocol(..)
    ) where

import           ClassyPrelude
import           Control.Concurrent.Async      (race_)
import           Data.Maybe                    (fromJust)

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

import qualified Network.Connection            as NC
import           Protocols
import           System.IO                     (IOMode (ReadWriteMode))
import           System.Timeout

import qualified System.Log.Logger             as LOG


data TunnelSettings = TunnelSettings
  { proxySetting :: Maybe (HostName, PortNumber)
  , localBind    :: HostName
  , localPort    :: PortNumber
  , serverHost   :: HostName
  , serverPort   :: PortNumber
  , destHost     :: HostName
  , destPort     :: PortNumber
  , protocol     :: Protocol
  , useTls       :: Bool
  }

instance Show TunnelSettings where
  show TunnelSettings{..} =  localBind <> ":" <> show localPort
                             <> (if isNothing proxySetting
                                 then mempty
                                 else " <==PROXY==> " <> fst (fromJust proxySetting) <> ":" <> (show . snd . fromJust $ proxySetting)
                                )
                             <> " <==" <> (if useTls then "WSS" else "WS") <> "==> "
                             <> serverHost <> ":" <> show serverPort
                             <> " <==" <>  show protocol <> "==> " <> destHost <> ":" <> show destPort


data Connection = Connection
  { read          :: IO (Maybe ByteString)
  , write         :: ByteString -> IO ()
  , close         :: IO ()
  , rawConnection :: Maybe N.Socket
  }


data Error = ProxyConnectionError String
           | ProxyForwardError String
           | LocalServerError String
           | TunnelError String
           | WebsocketError String
           | TlsError String
           | Other String
           deriving (Show, Read)

class ToConnection a where
  toConnection :: a -> Connection

instance ToConnection WS.Connection where
  toConnection conn = Connection { read = Just <$> WS.receiveData conn
                                 , write = WS.sendBinaryData conn
                                 , close = WS.sendClose conn (mempty :: LByteString)
                                 , rawConnection = Nothing
                                 }

instance ToConnection N.AppData where
  toConnection conn = Connection { read = Just <$> N.appRead conn
                                 , write = N.appWrite conn
                                 , close = N.appCloseConnection conn
                                 , rawConnection = Nothing
                                 }

instance ToConnection UdpAppData where
  toConnection conn = Connection { read = Just <$> appRead conn
                                 , write = appWrite conn
                                 , close = return ()
                                 , rawConnection = Nothing
                                 }

instance ToConnection NC.Connection where
  toConnection conn = Connection { read = Just <$> NC.connectionGetChunk conn
                                 , write = NC.connectionPut conn
                                 , close = NC.connectionClose conn
                                 , rawConnection = Nothing
                                 }

rrunTCPClient :: N.ClientSettings -> (Connection -> IO a) -> IO a
rrunTCPClient cfg app = bracket
    (N.getSocketFamilyTCP (N.getHost cfg) (N.getPort cfg) (N.getAddrFamily cfg))
    (\r -> catch (N.sClose $ fst r) (\(_ :: SomeException) -> return ()))
    (\(s, _) -> app Connection
        { read = Just <$> N.safeRecv s (N.getReadBufferSize cfg)
        , write = N.sendAll s
        , close = N.sClose s
        , rawConnection = Just s
        })

connectionToStream :: Connection -> IO WS.Stream
connectionToStream Connection{..} =  WS.makeStream read (write . toStrict . fromJust)

--
--  Pipes
--
tunnelingClientP :: TunnelSettings -> (Connection -> IO (Either Error ())) -> (Connection -> IO (Either Error ()))
tunnelingClientP cfg@TunnelSettings{..} app conn = do
  debug "Oppening Websocket stream"
  stream <- connectionToStream conn
  ret <- onError $ WS.runClientWithStream stream serverHost (toPath cfg) WS.defaultConnectionOptions [] (app . toConnection)

  debug "Closing Websocket stream"
  return ret

  where
    onError = flip catch (\(e :: SomeException) -> return . Left . WebsocketError $ show e)


tlsClientP :: TunnelSettings -> (Connection -> IO (Either Error ())) -> (Connection -> IO (Either Error ()))
tlsClientP TunnelSettings{..} app conn = do
  let tlsSettings = NC.TLSSettingsSimple { NC.settingDisableCertificateValidation = True
                                         , NC.settingDisableSession = False
                                         , NC.settingUseServerName = False
                                         }
  let connectionParams = NC.ConnectionParams { NC.connectionHostname = serverHost
                                             , NC.connectionPort = serverPort
                                             , NC.connectionUseSecure = Just tlsSettings
                                             , NC.connectionUseSocks = Nothing
                                             }

  debug "Doing tls Handshake"

  ret <- onError $ do
    context <- NC.initConnectionContext
    let socket = fromJust $ rawConnection conn
    h <- N.socketToHandle socket ReadWriteMode

    connection <- NC.connectFromHandle context h connectionParams
    finally (app (toConnection connection)) (hClose h)

  debug "Closing TLS"
  return ret

  where
    onError = flip catch (\(e :: SomeException) -> return . Left . TlsError $ show e)


--
--  Connectors
--
tcpConnection :: TunnelSettings -> (Connection -> IO (Either Error ())) -> IO (Either Error ())
tcpConnection TunnelSettings{..} app = do
  debug $ "Oppening tcp connection to " <> fromString serverHost <> ":" <> show (fromIntegral serverPort :: Int)

  ret <- onError $ rrunTCPClient (N.clientSettingsTCP (fromIntegral serverPort) (fromString serverHost)) app


  debug $ "Closing tcp connection to " <> fromString serverHost <> ":" <> show (fromIntegral serverPort :: Int)
  return ret

  where
    onError = flip catch (\(e :: SomeException) -> return $ if take 10 (show e) == "user error" then Right () else Left $ TunnelError $ show e)



httpProxyConnection :: (HostName, PortNumber) -> TunnelSettings -> (Connection -> IO (Either Error ())) -> IO (Either Error ())
httpProxyConnection (host, port) TunnelSettings{..} app = do
  debug $ "Oppening tcp connection to proxy " <> fromString host <> ":" <> show (fromIntegral port :: Int)

  ret <- onError $ rrunTCPClient (N.clientSettingsTCP (fromIntegral port) (fromString host)) $ \conn -> do
    _ <- sendConnectRequest conn
    responseM <- timeout (1000000 * 10) $ readConnectResponse mempty conn
    let response = fromMaybe "No response of the proxy after 10s" responseM

    if isAuthorized response
    then app conn
    else return . Left . ProxyForwardError $ BC.unpack response

  debug $ "Closing tcp connection to proxy " <> fromString host <> ":" <> show (fromIntegral port :: Int)
  return ret

  where
    sendConnectRequest h = write h $ "CONNECT " <> fromString serverHost <> ":" <> fromString (show serverPort) <> " HTTP/1.0\r\n"
                                   <> "Host: " <> fromString serverHost <> ":" <> fromString (show serverPort) <> "\r\n\r\n"

    readConnectResponse buff conn = do
      response <- fromJust <$> read conn
      if "\r\n\r\n" `BC.isInfixOf` response
      then return $ buff <> response
      else readConnectResponse (buff <> response) conn

    isAuthorized response = " 200 " `BC.isInfixOf` response

    onError = flip catch (\(e :: SomeException) -> return $ if take 10 (show e) == "user error"
                                                            then Right ()
                                                            else Left $ ProxyConnectionError $ show e)

--
--  Client
--
runClient :: TunnelSettings -> IO ()
runClient cfg@TunnelSettings{..} = do
  let withEndPoint = if isJust proxySetting then httpProxyConnection (fromJust proxySetting) cfg else tcpConnection cfg
  let doTlsIf tlsNeeded app = if tlsNeeded then tlsClientP cfg app else app
  let runTunnelClient = tunnelingClientP cfg
  let withTunnel app = withEndPoint (doTlsIf useTls . runTunnelClient $ app)

  let app localH = do
        ret <- withTunnel $ \remoteH -> do
          info $ "CREATE tunnel :: " <> show cfg
          ret <- remoteH `propagateRW` toConnection localH
          info $ "CLOSE tunnel :: " <> show cfg
          return ret

        handleError ret

  case protocol of
        UDP -> runUDPServer (localBind, localPort) app
        TCP -> runTCPServer (localBind, localPort) app

handleError :: Either Error () -> IO ()
handleError (Right ()) = return ()
handleError (Left errMsg) =
  case errMsg of
    ProxyConnectionError msg -> err "Cannot connect to the proxy" >> debugPP msg
    ProxyForwardError msg    -> err "Connection not allowed by the proxy" >> debugPP msg
    TunnelError msg          -> err "Cannot establish the connection to the server" >> debugPP msg
    LocalServerError msg     -> err "Cannot create the localServer, port already binded ?" >> debugPP msg
    WebsocketError msg       -> err "Cannot establish websocket connection with the server" >> debugPP msg
    TlsError msg             -> err "Cannot do tls handshake with the server" >> debugPP msg
    Other msg                -> debugPP msg

  where
    debugPP msg = debug $ "====\n" <> msg <> "\n===="


propagateRW :: Connection -> Connection -> IO (Either Error ())
propagateRW hTunnel hOther =
  myTry $ race_ (propagateReads hTunnel hOther) (propagateWrites hTunnel hOther)

propagateReads :: Connection -> Connection -> IO ()
propagateReads hTunnel hOther = forever $ read hTunnel >>= write hOther . fromJust

propagateWrites :: Connection -> Connection -> IO ()
propagateWrites hTunnel hOther = do
  payload <- fromJust <$> read hOther
  unless (null payload) (write hTunnel payload >> propagateWrites hTunnel hOther)


myTry :: IO a -> IO (Either Error ())
myTry f = either (\(e :: SomeException) -> Left . Other $ show e) (const $ Right ()) <$> try f


--
--  Server
--

runTlsTunnelingServer :: (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runTlsTunnelingServer (bindTo, portNumber) isAllowed = do
  info $ "WAIT for TLS connection on " <> fromString bindTo <> ":" <> show portNumber

  N.runTCPServerTLS (N.tlsConfigBS (fromString bindTo) (fromIntegral portNumber) serverCertificate serverKey) $ \sClient ->
    runApp sClient WS.defaultConnectionOptions (serverEventLoop isAllowed)

  info "SHUTDOWN server"

  where
    runApp :: N.AppData -> WS.ConnectionOptions -> WS.ServerApp -> IO ()
    runApp appData opts  app= do
      stream <- WS.makeStream (Just <$> N.appRead appData) (N.appWrite appData . toStrict . fromJust)
      bracket (WS.makePendingConnectionFromStream stream opts)
              (\conn -> catch (WS.close $ WS.pendingStream conn) (\(_ :: SomeException) -> return ()))
              app

runTunnelingServer :: (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runTunnelingServer (host, port) isAllowed = do
  info $ "WAIT for connection on " <> fromString host <> ":" <> show port

  void $ N.runTCPServer (N.serverSettingsTCP (fromIntegral port) (fromString host)) $ \sClient ->
    runApp (fromJust $ N.appRawSocket sClient) WS.defaultConnectionOptions (serverEventLoop isAllowed)

  info "CLOSE server"

  where
    runApp :: N.Socket -> WS.ConnectionOptions -> WS.ServerApp -> IO ()
    runApp socket opts = bracket (WS.makePendingConnection socket opts)
                         (\conn -> catch (WS.close $ WS.pendingStream conn) (\(_ :: SomeException) -> return ()))

serverEventLoop :: ((ByteString, Int) -> Bool) -> WS.PendingConnection -> IO ()
serverEventLoop isAllowed pendingConn = do
  let path =  fromPath . WS.requestPath $ WS.pendingRequest pendingConn
  case path of
    Nothing -> info "Rejecting connection" >> WS.rejectRequest pendingConn "Invalid tunneling information"
    Just (!proto, !rhost, !rport) ->
      if not $ isAllowed (rhost, rport)
      then do
        info "Rejecting tunneling"
        WS.rejectRequest pendingConn "Restriction is on, You cannot request this tunneling"
      else do
        conn <- WS.acceptRequest pendingConn
        case proto of
          UDP -> runUDPClient (BC.unpack rhost, fromIntegral rport) (\cnx -> void $ toConnection conn `propagateRW` toConnection cnx)
          TCP -> runTCPClient (BC.unpack rhost, fromIntegral rport) (\cnx -> void $ toConnection conn `propagateRW` toConnection cnx)


runServer :: Bool -> (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runServer useTLS = if useTLS then runTlsTunnelingServer else runTunnelingServer




-- openssl genrsa 512 > host.key
-- openssl req -new -x509 -nodes -sha1 -days 9999 -key host.key > host.cert
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



--
--  Commons
--


toPath :: TunnelSettings -> String
toPath TunnelSettings{..} = "/" <> toLower (show protocol) <> "/" <> destHost <> "/" <> show destPort

fromPath :: ByteString -> Maybe (Protocol, ByteString, Int)
fromPath path = let rets = BC.split '/' . BC.drop 1 $ path
  in do
    guard (length rets == 3)
    let [protocol, h, prt] = rets
    prt' <- readMay . BC.unpack $ prt :: Maybe Int
    proto <- readMay . toUpper . BC.unpack $ protocol :: Maybe Protocol
    return (proto, h, prt')
