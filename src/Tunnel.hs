{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}


module Tunnel
    ( runClient
    , runServer
    ) where

import           ClassyPrelude
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

import           Control.Monad.Except
import qualified Network.Connection            as NC
import           System.IO                     (IOMode (ReadWriteMode))
import           System.Timeout

import qualified Data.ByteString.Base64        as B64

import           Types
import           Protocols
import qualified Socks5
import           Logger
import qualified Credentials



rrunTCPClient :: N.ClientSettings -> (Connection -> IO a) -> IO a
rrunTCPClient cfg app = bracket
    (N.getSocketFamilyTCP (N.getHost cfg) (N.getPort cfg) (N.getAddrFamily cfg))
    (\r -> catch (N.close $ fst r) (\(_ :: SomeException) -> return ()))
    (\(s, _) -> app Connection
        { read = Just <$> N.safeRecv s (N.getReadBufferSize cfg)
        , write = N.sendAll s
        , close = N.close s
        , rawConnection = Just s
        })

--
--  Pipes
--
tunnelingClientP :: MonadError Error m => TunnelSettings -> (Connection -> IO (m ())) -> (Connection -> IO (m ()))
tunnelingClientP cfg@TunnelSettings{..} app conn = onError $ do
  debug "Oppening Websocket stream"

  stream <- connectionToStream conn
  ret <- WS.runClientWithStream stream serverHost (toPath cfg) WS.defaultConnectionOptions [] (app . toConnection)

  debug "Closing Websocket stream"
  return ret

  where
    connectionToStream Connection{..} =  WS.makeStream read (write . toStrict . fromJust)
    onError = flip catch (\(e :: SomeException) -> return . throwError . WebsocketError $ show e)


tlsClientP :: MonadError Error m => TunnelSettings -> (Connection -> IO (m ())) -> (Connection -> IO (m ()))
tlsClientP TunnelSettings{..} app conn = onError $ do
    debug "Doing tls Handshake"

    context <- NC.initConnectionContext
    let socket = fromJust $ rawConnection conn
    h <- N.socketToHandle socket ReadWriteMode

    connection <- NC.connectFromHandle context h connectionParams
    ret <- app (toConnection connection) `finally` hClose h

    debug "Closing TLS"
    return ret

  where
    onError = flip catch (\(e :: SomeException) -> return . throwError . TlsError $ show e)
    tlsSettings = NC.TLSSettingsSimple { NC.settingDisableCertificateValidation = True
                                       , NC.settingDisableSession = False
                                       , NC.settingUseServerName = False
                                       }
    connectionParams = NC.ConnectionParams { NC.connectionHostname = serverHost
                                           , NC.connectionPort = serverPort
                                           , NC.connectionUseSecure = Just tlsSettings
                                           , NC.connectionUseSocks = Nothing
                                           }


--
--  Connectors
--
tcpConnection :: MonadError Error m => TunnelSettings -> (Connection -> IO (m ())) -> IO (m ())
tcpConnection TunnelSettings{..} app = onError $ do
  debug $ "Oppening tcp connection to " <> fromString serverHost <> ":" <> show (fromIntegral serverPort :: Int)

  ret <- rrunTCPClient (N.clientSettingsTCP (fromIntegral serverPort) (fromString serverHost)) app

  debug $ "Closing tcp connection to " <> fromString serverHost <> ":" <> show (fromIntegral serverPort :: Int)
  return ret

  where
    onError = flip catch (\(e :: SomeException) -> return $ when (take 10 (show e) == "user error") (throwError $ TunnelError $ show e))



httpProxyConnection :: MonadError Error m => TunnelSettings -> (Connection -> IO (m ())) -> IO (m ())
httpProxyConnection TunnelSettings{..} app = onError $ do
  let settings = fromJust proxySetting
  debug $ "Oppening tcp connection to proxy " <> show settings

  ret <- rrunTCPClient (N.clientSettingsTCP (fromIntegral (port settings)) (BC.pack $ host settings)) $ \conn -> do
    _ <- sendConnectRequest settings conn
    responseM <- timeout (1000000 * 10) $ readConnectResponse mempty conn
    let response = fromMaybe "No response of the proxy after 10s" responseM

    if isAuthorized response
    then app conn
    else return . throwError . ProxyForwardError $ BC.unpack response

  debug $ "Closing tcp connection to proxy " <> show settings
  return ret

  where
    credentialsToHeader (user, password) = "Proxy-Authorization: Basic " <> B64.encode (user <> ":" <> password) <> "\r\n"
    sendConnectRequest settings h = write h $ "CONNECT " <> fromString serverHost <> ":" <> fromString (show serverPort) <> " HTTP/1.0\r\n"
                                  <> "Host: " <> fromString serverHost <> ":" <> fromString (show serverPort) <> "\r\n"
                                  <> maybe mempty credentialsToHeader (credentials settings)
                                  <> "\r\n"

    readConnectResponse buff conn = do
      response <- fromJust <$> read conn
      if "\r\n\r\n" `BC.isInfixOf` response
      then return $ buff <> response
      else readConnectResponse (buff <> response) conn

    isAuthorized response = " 200 " `BC.isInfixOf` response

    onError = flip catch (\(e :: SomeException) -> return $ when (take 10 (show e) == "user error") (throwError $ ProxyConnectionError $ show e))

--
--  Client
--
runClient :: TunnelSettings -> IO ()
runClient cfg@TunnelSettings{..} = do
  let withEndPoint = if isJust proxySetting then httpProxyConnection cfg else tcpConnection cfg
  let doTlsIf tlsNeeded app = if tlsNeeded then tlsClientP cfg app else app
  let withTunnel cfg' app = withEndPoint (doTlsIf useTls . tunnelingClientP cfg' $ app)

  let app cfg' localH = do
        ret <- withTunnel cfg' $ \remoteH -> do
          info $ "CREATE tunnel :: " <> show cfg'
          ret <- remoteH <==> toConnection localH
          info $ "CLOSE tunnel :: " <> show cfg'
          return ret

        handleError ret

  case protocol of
        UDP -> runUDPServer (localBind, localPort) (app cfg)
        TCP -> runTCPServer (localBind, localPort) (app cfg)
        SOCKS5 -> runSocks5Server (Socks5.ServerSettings localPort localBind) cfg app





--
--  Server
--
runTlsTunnelingServer :: (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runTlsTunnelingServer endPoint@(bindTo, portNumber) isAllowed = do
  info $ "WAIT for TLS connection on " <> toStr endPoint

  N.runTCPServerTLS (N.tlsConfigBS (fromString bindTo) (fromIntegral portNumber) Credentials.certificate Credentials.key) $ \sClient ->
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
runTunnelingServer endPoint@(host, port) isAllowed = do
  info $ "WAIT for connection on " <> toStr endPoint

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
          UDP -> runUDPClient (BC.unpack rhost, fromIntegral rport) (\cnx -> void $ toConnection conn <==> toConnection cnx)
          TCP -> runTCPClient (BC.unpack rhost, fromIntegral rport) (\cnx -> void $ toConnection conn <==> toConnection cnx)


runServer :: Bool -> (HostName, PortNumber) -> ((ByteString, Int) -> Bool) -> IO ()
runServer useTLS = if useTLS then runTlsTunnelingServer else runTunnelingServer




--
--  Commons
--
toPath :: TunnelSettings -> String
toPath TunnelSettings{..} = "/" <> toLower (show $ if protocol == SOCKS5 then TCP else protocol) <> "/" <> destHost <> "/" <> show destPort

fromPath :: ByteString -> Maybe (Protocol, ByteString, Int)
fromPath path = let rets = BC.split '/' . BC.drop 1 $ path
  in do
    guard (length rets == 3)
    let [protocol, h, prt] = rets
    prt' <- readMay . BC.unpack $ prt :: Maybe Int
    proto <- readMay . toUpper . BC.unpack $ protocol :: Maybe Protocol
    return (proto, h, prt')

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

myTry :: MonadError Error m => IO a -> IO (m ())
myTry f = either (\(e :: SomeException) -> throwError . Other $ show e) (const $ return ()) <$> try f

(<==>) :: Connection -> Connection -> IO (Either Error ())
(<==>) hTunnel hOther =
  myTry $ race_ (propagateReads hTunnel hOther) (propagateWrites hTunnel hOther)

propagateReads :: Connection -> Connection -> IO ()
propagateReads hTunnel hOther = forever $ read hTunnel >>= write hOther . fromJust


propagateWrites :: Connection -> Connection -> IO ()
propagateWrites hTunnel hOther = do
  payload <- fromJust <$> read hOther
  unless (null payload) (write hTunnel payload >> propagateWrites hTunnel hOther)
