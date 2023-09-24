{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           ClassyPrelude          hiding (getArgs, head)
import           Data.CaseInsensitive  ( CI )
import qualified Data.CaseInsensitive as CI
import qualified Data.ByteString.Char8  as BC
import           Data.List              (head, (!!))
import           System.Console.CmdArgs
import           System.Environment     (getArgs, withArgs)

import qualified Logger
import           Tunnel
import           Types
import           Credentials
import           Control.Concurrent.Async as Async

data WsTunnel = WsTunnel
  { localToRemote   :: [String]
  -- , remoteToLocal  :: String
  , dynamicToRemote :: String
  , wsTunnelServer  :: String
  , udpMode         :: Bool
  , udpTimeout      :: Int
  , proxy           :: String
  , soMark          :: Int
  , verbose         :: Bool
  , quiet           :: Bool
  , pathPrefix      :: String
  , hostHeader      :: String
  , tlsSNI          :: String
  , tlsVerifyCertificate  :: Bool
  , websocketPingFrequencySec :: Int
  , wsTunnelCredentials :: String
  , customHeaders   :: [String]
  , serverMode      :: Bool
  , restrictTo      :: String
  , tlsCertificate  :: FilePath
  , tlsKey          :: FilePath
  } deriving (Show, Data, Typeable)

data WsServerInfo = WsServerInfo
  { useTls :: !Bool
  , host   :: !String
  , port   :: !Int
  } deriving (Show)

data TunnelInfo = TunnelInfo
  { localHost  :: !String
  , localPort  :: !Int
  , remoteHost :: !String
  , remotePort :: !Int
  } deriving (Show)


cmdLine :: WsTunnel
cmdLine = WsTunnel
  { localToRemote  = def &= explicit &= name "L" &= name "localToRemote" &= typ "[BIND:]PORT:HOST:PORT"
                         &= help "Listen on local and forwards traffic from remote. Can be used multiple time" &= groupname "Client options"
  -- , remoteToLocal  = def &= explicit &= name "R" &= name "RemoteToLocal" &= typ "[BIND:]PORT:HOST:PORT"
  --                        &= help "Listen on remote and forward traffic from local"
  , dynamicToRemote= def &= explicit &= name "D" &= name "dynamicToRemote" &= typ "[BIND:]PORT"
                         &= help "Listen on local and dynamically (with socks5 proxy) forwards traffic from remote" &= groupname "Client options"
  , udpMode        = def &= explicit &= name "u" &= name "udp" &= help "forward UDP traffic instead of TCP" &= groupname "Client options"
  , udpTimeout     = def &= explicit &= name "udpTimeoutSec" &= help "When using udp forwarding, timeout in seconds after when the tunnel connection is closed. Default 30sec, -1 means no timeout"
                         &= groupname "Client options"
  , customHeaders  = def &= explicit &= name "H" &= name "customHeaders" &= help "Send custom headers in the upgrade request. Can be used multiple time"
                         &= typ "\"HeaderName: HeaderValue\"" &= groupname "Client options"
  , pathPrefix     = def &= explicit &= name "upgradePathPrefix"
                         &= help "Use a specific prefix that will show up in the http path in the upgrade request. Useful if you need to route requests server side but don't have vhosts"
                         &= typ "String" &= groupname "Client options"
  , wsTunnelCredentials
                   = def &= explicit &= name "upgradeCredentials"
                         &= help "Credentials for the Basic HTTP authorization type sent with the upgrade request."
                         &= typ "USER[:PASS]"
  , proxy          = def &= explicit &= name "p" &= name "httpProxy"
                         &= help "If set, will use this proxy to connect to the server" &= typ "USER:PASS@HOST:PORT"
  , hostHeader     = def &= explicit &= name "hostHeader" &= groupname "Client options"
                         &= help "If set, add the custom string as host http header" &= typ "String" &= groupname "Client options"
  , tlsSNI         = def &= explicit &= name "tlsSNI" &= groupname "Client options"
                         &= help "If set, use custom string in the SNI during TLS handshake" &= typ "String" &= groupname "Client options"
  , tlsVerifyCertificate = def &= explicit &= name "tlsVerifyCertificate" &= groupname "Client options"
                         &= help "Verify tls server certificate. Default to false"
  , soMark         = def &= explicit &= name "soMark"
                         &= help "(linux only) Mark network packet with SO_MARK sockoption with the specified value. You need to use {root, sudo, capabilities} to run wstunnel when using this option" &= typ "int"
  , websocketPingFrequencySec = def &= explicit &= name "websocketPingFrequencySec"
                         &= help "do a hearthbeat ping every x seconds to maintain websocket connection" &= typ "int"
  , wsTunnelServer = def &= argPos 0 &= typ "ws[s]://wstunnelServer[:port]"

  , serverMode     = def &= explicit &= name "server"
                         &= help "Start a server that will forward traffic for you" &= groupname "Server options"
  , restrictTo     = def &= explicit &= name "r" &= name "restrictTo" &= groupname "Server options"
                         &= help "Accept traffic to be forwarded only to this service" &= typ "HOST:PORT"
  , tlsCertificate = def &= explicit &= name "tlsCertificate" &= groupname "Server options"
                         &= help "[optional] provide a custom tls certificate (.crt) that the server will use instead of the embeded one" &= typFile
  , tlsKey         = def &= explicit &= name "tlsKey" &= groupname "Server options"
                         &= help "[optional] provide a custom tls key (.key) that the server will use instead of the embeded one" &= typFile
  , verbose        = def &= groupname "Common options" &= help "Print debug information"
  , quiet          = def &= help "Print only errors" &= groupname "Common options"
  } &= summary (   "Use the websockets protocol to tunnel {TCP,UDP} traffic\n"
                ++ "wsTunnelClient <---> wsTunnelServer <---> RemoteHost\n"
                ++ "Use secure connection (wss://) to bypass proxies\n"
                ++ "Version: 6.0"
               )
    &= helpArg [explicit, name "help", name "h", groupname "Common options"]


toPort :: String -> Int
toPort "stdio" = 0
toPort str = case readMay str of
                  Just por -> por
                  Nothing  -> error $ "Invalid port number `" ++ str ++ "`"

parseServerInfo :: WsServerInfo -> String -> WsServerInfo
parseServerInfo server []                           = server
parseServerInfo server ('w':'s':':':'/':'/':xs)     = parseServerInfo (server {Main.useTls = False, Main.port = 80}) xs
parseServerInfo server ('w':'s':'s':':':'/':'/':xs) = parseServerInfo (server {Main.useTls = True, Main.port = 443}) xs
parseServerInfo server (':':prt)                    = server {Main.port = toPort prt}
parseServerInfo server ('[':xs)                     = parseServerInfo (server {Main.host = BC.unpack . BC.init . fst $ BC.spanEnd (/= ']') (BC.pack xs)}) (BC.unpack . snd $ BC.spanEnd (/= ']') (BC.pack xs))
parseServerInfo server hostPath                     = parseServerInfo (server {Main.host = takeWhile (/= ':') hostPath}) (dropWhile (/= ':') hostPath)


parseTunnelInfo :: String -> TunnelInfo
parseTunnelInfo strr = do
  let str = BC.pack strr
  if BC.count ']' str <= 0 then
    mkIPv4 $ BC.unpack <$> BC.split ':' str
  else
    mkIPv6 $ str

  where
    mkIPv4 [lPort, host, rPort]     = TunnelInfo {localHost = "127.0.0.1", Main.localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mkIPv4 [bind,lPort, host,rPort] = TunnelInfo {localHost = bind, Main.localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mkIPv4 _                        = error $  "Invalid tunneling information `" ++ strr ++ "`, please use format [BIND:]PORT:HOST:PORT"

    mkIPv6 str = do
     let !(localHost, remain) = if BC.head str == '[' then
           BC.drop 2 <$> BC.span (/= ']') (BC.drop 1 str)
         else if BC.head str < '0' || BC.head str > '9' then
           BC.drop 1 <$> BC.span (/= ':') str
         else
           ("", str)

     let (remain, rPort) = first BC.init . BC.spanEnd (/= ':') $ str
     let (remain2, remoteHost) = if BC.last remain == ']' then
           first (BC.init . BC.init) $ BC.spanEnd (/= '[') (BC.init remain)
         else
           first BC.init $ BC.spanEnd (/= ':') remain

     let (remain3, lPort) = BC.spanEnd (/= ':') $ remain2
     if remain3 == mempty then
       TunnelInfo {localHost = "::1", Main.localPort = toPort (BC.unpack lPort), remoteHost = (BC.unpack remoteHost), remotePort = toPort (BC.unpack rPort)}
     else
       let localHost = BC.filter (\c -> c /= '[' && c /= ']') (BC.init remain3) in
       TunnelInfo {localHost = BC.unpack localHost, Main.localPort = toPort (BC.unpack lPort), remoteHost = (BC.unpack remoteHost), remotePort = toPort (BC.unpack rPort)}



parseRestrictTo :: String -> ((ByteString, Int) -> Bool)
parseRestrictTo "" = const True
parseRestrictTo str = let !(!h, !p) = fromMaybe (error "Invalid Parameter restart") parse
  in (\(!hst, !port) -> hst == h && port == p)
  where
    parse = do
              let (host, port) = BC.spanEnd (/= ':') (BC.pack str)
              guard (host /= mempty)
              portNumber <- readMay . BC.unpack $ port :: Maybe Int
              return (BC.filter (\c -> c /= '[' && c /= ']') (BC.init host), portNumber)

parseProxyInfo :: String -> Maybe ProxySettings
parseProxyInfo str = do
  let ret = BC.split ':' (BC.pack str)

  guard (length ret >= 2)
  if length ret == 3
  then do
    portNumber <- readMay $ BC.unpack $ ret !! 2 :: Maybe Int
    let cred = (head ret, head (BC.split '@' (ret !! 1)))
    let h = BC.split '@' (ret !! 1) !! 1
    return $ ProxySettings (BC.unpack h) (fromIntegral portNumber) (Just cred)
  else if length ret == 2
  then do
    portNumber <- readMay . BC.unpack $ ret !! 1 :: Maybe Int
    return $ ProxySettings (BC.unpack $ head ret) (fromIntegral portNumber) Nothing
    else Nothing

parseCustomHeader :: String -> (CI ByteString, ByteString)
parseCustomHeader header = (CI.mk . BC.pack $ takeWhile (/= ':') header, BC.pack . dropWhile (\c -> c == ' ' || c == ':') $ (dropWhile (/= ':') header))


main :: IO ()
main = do
  args <- getArgs
  cfg' <- if null args then withArgs ["--help"] (cmdArgs cmdLine) else cmdArgs cmdLine
  let cfg = cfg' { pathPrefix = if pathPrefix cfg' == mempty then "wstunnel" else pathPrefix cfg'
                 , Main.udpTimeout = if Main.udpTimeout cfg' == 0 then 30 * 10^(6 :: Int)
                                     else if Main.udpTimeout cfg' == -1 then -1
                                     else Main.udpTimeout cfg' * 10^(6:: Int)
                 , Main.websocketPingFrequencySec = if Main.websocketPingFrequencySec cfg' == 0
                                                    then 30
                                                    else Main.websocketPingFrequencySec cfg'
                 }

  let serverInfo = parseServerInfo (WsServerInfo False "" 0) (wsTunnelServer cfg)
  Logger.init (if quiet cfg then Logger.QUIET
                            else if verbose cfg
                            then Logger.VERBOSE
                            else Logger.NORMAL)

  _ <- writeIORef sO_MARK_Value (soMark cfg)
  runApp cfg serverInfo
  putStrLn "Goodbye !"
  return ()


runApp :: WsTunnel -> WsServerInfo -> IO ()
runApp cfg serverInfo
  -- server mode
  | serverMode cfg = do
      putStrLn $ "Starting server with opts " <> tshow serverInfo
      key <- if Main.tlsKey cfg /= mempty then readFile (Main.tlsKey cfg) else return Credentials.key
      certificate <- if Main.tlsCertificate cfg /= mempty then readFile (Main.tlsCertificate cfg) else return Credentials.certificate
      let tls = if Main.useTls serverInfo then Just (certificate, key) else Nothing
      runServer tls (Main.host serverInfo, fromIntegral $ Main.port serverInfo) (parseRestrictTo $ restrictTo cfg)

  -- -L localToRemote tunnels
  | not . null $ localToRemote cfg = do
      let tunnelInfos = parseTunnelInfo <$> localToRemote cfg
      let tunnelSettings = tunnelInfos >>= \tunnelInfo -> 
                if Main.localPort tunnelInfo == 0 then [toStdioLocalToRemoteTunnelSetting cfg serverInfo tunnelInfo] 
                else if udpMode cfg then [toUdpLocalToRemoteTunnelSetting cfg serverInfo tunnelInfo] 
                else [toTcpLocalToRemoteTunnelSetting cfg serverInfo tunnelInfo]
      Async.mapConcurrently_ runClient tunnelSettings

  -- -D dynamicToRemote tunnels
  | not . null $ dynamicToRemote cfg = do
      let tunnelSetting = toDynamicTunnelSetting cfg serverInfo . parseTunnelInfo $ dynamicToRemote cfg ++ ":127.0.0.1:1212"
      runClient tunnelSetting

  | otherwise = do
      putStrLn "Cannot parse correctly the command line. Please fill an issue"

  where
    toStdioLocalToRemoteTunnelSetting cfg serverInfo (TunnelInfo lHost lPort rHost rPort)  =
      TunnelSettings {
            localBind = lHost
          , Types.localPort = fromIntegral lPort
          , serverHost = Main.host serverInfo
          , serverPort = fromIntegral $ Main.port serverInfo
          , destHost = rHost
          , destPort = fromIntegral rPort
          , Types.useTls = Main.useTls serverInfo
          , protocol = STDIO
          , proxySetting = parseProxyInfo (proxy cfg)
          , useSocks = False
          , upgradePrefix = pathPrefix cfg
          , upgradeCredentials = BC.pack $ wsTunnelCredentials cfg
          , udpTimeout = Main.udpTimeout cfg
          , tlsSNI = BC.pack $ Main.tlsSNI cfg
          , tlsVerifyCertificate = Main.tlsVerifyCertificate cfg
          , hostHeader = BC.pack $ Main.hostHeader cfg
          , websocketPingFrequencySec = Main.websocketPingFrequencySec cfg
          , customHeaders = parseCustomHeader <$> Main.customHeaders cfg
      }

    toTcpLocalToRemoteTunnelSetting cfg serverInfo (TunnelInfo lHost lPort rHost rPort)  =
      TunnelSettings {
            localBind = lHost
          , Types.localPort = fromIntegral lPort
          , serverHost = Main.host serverInfo
          , serverPort = fromIntegral $ Main.port serverInfo
          , destHost = rHost
          , destPort = fromIntegral rPort
          , Types.useTls = Main.useTls serverInfo
          , protocol = TCP
          , proxySetting = parseProxyInfo (proxy cfg)
          , useSocks = False
          , upgradePrefix = pathPrefix cfg
          , upgradeCredentials = BC.pack $ wsTunnelCredentials cfg
          , udpTimeout = Main.udpTimeout cfg
          , tlsSNI = BC.pack $ Main.tlsSNI cfg
          , tlsVerifyCertificate = Main.tlsVerifyCertificate cfg
          , hostHeader = BC.pack $ Main.hostHeader cfg
          , websocketPingFrequencySec = Main.websocketPingFrequencySec cfg
          , customHeaders = parseCustomHeader <$> Main.customHeaders cfg
      }

    toUdpLocalToRemoteTunnelSetting cfg serverInfo (TunnelInfo lHost lPort rHost rPort) =
      TunnelSettings {
            localBind = lHost
          , Types.localPort = fromIntegral lPort
          , serverHost = Main.host serverInfo
          , serverPort = fromIntegral $ Main.port serverInfo
          , destHost = rHost
          , destPort = fromIntegral rPort
          , Types.useTls = Main.useTls serverInfo
          , protocol = UDP
          , proxySetting = parseProxyInfo (proxy cfg)
          , useSocks = False
          , upgradePrefix = pathPrefix cfg
          , upgradeCredentials = BC.pack $ wsTunnelCredentials cfg
          , udpTimeout = Main.udpTimeout cfg
          , tlsSNI = BC.pack $ Main.tlsSNI cfg
          , tlsVerifyCertificate = Main.tlsVerifyCertificate cfg
          , hostHeader = BC.pack $ Main.hostHeader cfg
          , websocketPingFrequencySec = Main.websocketPingFrequencySec cfg
          , customHeaders = parseCustomHeader <$> Main.customHeaders cfg
      }

    toDynamicTunnelSetting cfg serverInfo (TunnelInfo lHost lPort _ _) =
      TunnelSettings {
            localBind = lHost
          , Types.localPort = fromIntegral lPort
          , serverHost = Main.host serverInfo
          , serverPort = fromIntegral $ Main.port serverInfo
          , destHost = ""
          , destPort = 0
          , Types.useTls = Main.useTls serverInfo
          , protocol = SOCKS5
          , proxySetting = parseProxyInfo (proxy cfg)
          , useSocks = True
          , upgradePrefix = pathPrefix cfg
          , upgradeCredentials = BC.pack $ wsTunnelCredentials cfg
          , udpTimeout = Main.udpTimeout cfg
          , tlsSNI = BC.pack $ Main.tlsSNI cfg
          , tlsVerifyCertificate = Main.tlsVerifyCertificate cfg
          , hostHeader = BC.pack $ Main.hostHeader cfg
          , websocketPingFrequencySec = Main.websocketPingFrequencySec cfg
          , customHeaders = parseCustomHeader <$> Main.customHeaders cfg
      }
