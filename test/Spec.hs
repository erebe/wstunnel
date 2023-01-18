{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE OverloadedStrings  #-}

import           ClassyPrelude          hiding (getArgs, head)
import qualified Logger
import qualified Network.Socket                as N hiding (recv, recvFrom,
                                                     send, sendTo)
import qualified Network.Socket.ByteString     as N
import qualified Data.Conduit.Network.TLS      as N
import qualified Data.Streaming.Network        as N

import           Data.CaseInsensitive  ( CI )
import qualified Data.CaseInsensitive as CI
import           Control.Concurrent.Async as Async
import 		 Data.ByteString (hPutStr)
import 		 Control.Concurrent (threadDelay)
import           Test.Hspec
import           Data.Binary (decode, encode)


import Tunnel
import Types
import Protocols
import Credentials
import qualified Socks5 as Socks5

testTCPLocalToRemote :: Bool -> IO ()
testTCPLocalToRemote useTLS = do

  Logger.init Logger.VERBOSE

  success <- newIORef False
  let needle = "toto"

  -- SERVER
  let serverPort = 8080
  let tls = if useTLS then Just (Credentials.certificate, Credentials.key) else Nothing
  let serverWithoutTLS = runServer tls ("0.0.0.0", serverPort) (const True)

  -- CLIENT
  let tunnelSetting = TunnelSettings {
            localBind = "localhost"
          , Types.localPort = fromIntegral 8081
          , serverHost = "localhost"
          , serverPort = fromIntegral serverPort
          , destHost = "localhost"
          , destPort = fromIntegral 8082
          , Types.useTls = useTLS
          , protocol = TCP
          , proxySetting = Nothing
          , useSocks = False
          , upgradePrefix = "wstunnel"
          , udpTimeout = 0
          , upgradeCredentials = ""
          , hostHeader = "toto.com"
          , tlsSNI = "toto.com"
          , websocketPingFrequencySec = 30
          , customHeaders = [(CI.mk "toto", "tata"), (CI.mk "titi", "tutu")]
          , tlsVerifyCertificate = False
      }
  let client = runClient tunnelSetting

  -- Remote STUB ENDPOINT
  let remoteSetting = N.serverSettingsTCP (fromIntegral 8082) "localhost"
  let remoteServerEndpoint = N.runTCPServer remoteSetting $ (\sClient -> do N.appRead sClient >>= \payload -> if payload == needle then writeIORef success True else writeIORef success False)

  -- local STUB ENDPOINT
  let localClient = rrunTCPClient (N.clientSettingsTCP (fromIntegral 8081) "localhost") (\cnx -> write cnx needle)

  putStrLn "Starting remote endpoint"
  Async.async $ timeout (10 * 10^6) remoteServerEndpoint
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel server"
  Async.async $ timeout (10 * 10^6) serverWithoutTLS
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel client"
  Async.async $ timeout (10 * 10^6) client
  threadDelay (1 * 10^6)

  putStrLn "Writing data to the pipeline"
  _ <- localClient
  threadDelay (7 * 10^6)

  isSuccess <- readIORef success
  if not isSuccess 
  then throwString "Tunnel is not working"
  else putStrLn "Success"

testUDPLocalToRemote :: Bool -> IO ()
testUDPLocalToRemote useTLS = do

  Logger.init Logger.VERBOSE

  success <- newIORef False
  let needle = "toto"

  -- SERVER
  let serverPort = 8080
  let tls = if useTLS then Just (Credentials.certificate, Credentials.key) else Nothing
  let serverWithoutTLS = runServer tls ("0.0.0.0", serverPort) (const True)

  -- CLIENT
  let tunnelSetting = TunnelSettings {
            localBind = "localhost"
          , Types.localPort = fromIntegral 8081
          , serverHost = "localhost"
          , serverPort = fromIntegral serverPort
          , destHost = "localhost"
          , destPort = fromIntegral 8082
          , Types.useTls = useTLS
          , protocol = UDP
          , proxySetting = Nothing
          , useSocks = False
          , upgradePrefix = "wstunnel"
          , udpTimeout = -1
          , upgradeCredentials = ""
          , hostHeader = "toto.com"
          , tlsSNI = "toto.com"
          , websocketPingFrequencySec = 30
          , customHeaders = [(CI.mk "toto", "tata"), (CI.mk "titi", "tutu")]
          , tlsVerifyCertificate = False
      }
  let client = runClient tunnelSetting

  -- Remote STUB ENDPOINT
  let remoteServerEndpoint = runUDPServer ("localhost", fromIntegral 8082) (-1) $ (\sClient -> do read (toConnection sClient) >>= \(Just payload) -> if payload == needle then writeIORef success True else writeIORef success False)

  -- local STUB ENDPOINT
  let localClient = runUDPClient ("localhost", fromIntegral 8081) (\cnx -> write (toConnection cnx) needle)

  putStrLn "Starting remote endpoint"
  Async.async $ timeout (10 * 10^6) remoteServerEndpoint
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel server"
  Async.async $ timeout (10 * 10^6) serverWithoutTLS
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel client"
  Async.async $ timeout (10 * 10^6) client
  threadDelay (1 * 10^6)

  putStrLn "Writing data to the pipeline"
  _ <- localClient
  threadDelay (7 * 10^6)

  isSuccess <- readIORef success
  if not isSuccess 
  then throwString "Tunnel is not working"
  else putStrLn "Success"

testSocks5Tunneling :: Bool -> IO ()
testSocks5Tunneling useTLS = do

  Logger.init Logger.VERBOSE

  success <- newIORef False
  let needle = "toto"

  -- SERVER
  let serverPort = 8080
  let tls = if useTLS then Just (Credentials.certificate, Credentials.key) else Nothing
  let serverWithoutTLS = runServer tls ("0.0.0.0", serverPort) (const True)

  -- CLIENT
  let tunnelSetting = TunnelSettings {
            localBind = "localhost"
          , Types.localPort = fromIntegral 8081
          , serverHost = "localhost"
          , serverPort = fromIntegral serverPort
          , destHost = ""
          , destPort = 0
          , Types.useTls = useTLS
          , protocol = SOCKS5
          , proxySetting = Nothing
          , useSocks = False
          , upgradePrefix = "wstunnel"
          , udpTimeout = -1
          , upgradeCredentials = ""
          , hostHeader = "toto.com"
          , tlsSNI = "toto.com"
          , websocketPingFrequencySec = 30
          , customHeaders = [(CI.mk "toto", "tata"), (CI.mk "titi", "tutu")]
          , tlsVerifyCertificate = False
      }
  let client = runClient tunnelSetting

  -- Remote STUB ENDPOINT
  let remoteSetting = N.serverSettingsTCP (fromIntegral 8082) "localhost"
  let remoteServerEndpoint = N.runTCPServer remoteSetting $ (\sClient -> do N.appRead sClient >>= \payload -> if payload == needle then writeIORef success True else writeIORef success False)


  putStrLn "Starting remote endpoint"
  Async.async $ timeout (10 * 10^6) remoteServerEndpoint
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel server"
  Async.async $ timeout (10 * 10^6) serverWithoutTLS
  threadDelay (1 * 10^6)

  putStrLn "Starting wstunnel client"
  Async.async $ timeout (10 * 10^6) client
  threadDelay (1 * 10^6)

  putStrLn "Writing data to the pipeline"
  rrunTCPClient (N.clientSettingsTCP (fromIntegral 8081) "localhost") $ \cnx -> do 
    write cnx (toStrict . encode $ Socks5.RequestAuth (fromIntegral Socks5.socksVersion) (fromList [Socks5.NoAuth]))
    _ <- read cnx 
    write cnx (toStrict . encode $ Socks5.Request (fromIntegral Socks5.socksVersion) Socks5.Connect "localhost" 8082 Socks5.DOMAIN_NAME)
    _ <- read cnx 
    write cnx needle

  threadDelay (7 * 10^6)

  isSuccess <- readIORef success
  if not isSuccess 
  then throwString "Tunnel is not working"
  else putStrLn "Success"

main :: IO ()
main = hspec $ do
    describe "Socks5 tunneling" $ do
      it "Testing socks5 -D without TLS" $ do
       testSocks5Tunneling False
      it "Testing socks5 -D with TLS" $ do
       testSocks5Tunneling True

    describe "TCP tunneling" $ do
      it "Testing TCP -L without TLS" $ do
       testTCPLocalToRemote False 
      it "Testing TCP -L with TLS" $ do
       testTCPLocalToRemote True

    describe "UDP tunneling" $ do
      it "Testing UDP -L without TLS" $ do
       testUDPLocalToRemote False
      it "Testing UDP -L with TLS" $ do
       testUDPLocalToRemote True

