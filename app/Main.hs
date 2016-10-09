{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           ClassyPrelude          hiding (getArgs, head)
import qualified Data.ByteString.Char8  as BC
import           Data.List              (head, (!!))
import           Data.Maybe             (fromMaybe)
import           System.Console.CmdArgs
import           System.Environment     (getArgs, withArgs)

import qualified Logger
import           Tunnel
import           Types

data WsTunnel = WsTunnel
  { localToRemote   :: String
  -- , remoteToLocal  :: String
  , dynamicToRemote :: String
  , wsTunnelServer  :: String
  , udpMode         :: Bool
  , proxy           :: String
  , serverMode      :: Bool
  , restrictTo      :: String
  , verbose         :: Bool
  , quiet           :: Bool
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
                         &= help "Listen on local and forwards traffic from remote" &= groupname "Client options"
  -- , remoteToLocal  = def &= explicit &= name "R" &= name "RemoteToLocal" &= typ "[BIND:]PORT:HOST:PORT"
  --                        &= help "Listen on remote and forward traffic from local"
  , dynamicToRemote= def &= explicit &= name "D" &= name "dynamicToRemote" &= typ "[BIND:]PORT"
                         &= help "Listen on local and dynamically (with socks5 proxy) forwards traffic from remote" &= groupname "Client options"
  , udpMode        = def &= explicit &= name "u" &= name "udp" &= help "forward UDP traffic instead of TCP"
  , proxy          = def &= explicit &= name "p" &= name "httpProxy"
                         &= help "If set, will use this proxy to connect to the server" &= typ "USER:PASS@HOST:PORT"
  , wsTunnelServer = def &= argPos 0 &= typ "ws[s]://wstunnelServer[:port]"

  , serverMode     = def &= explicit &= name "server"
                         &= help "Start a server that will forward traffic for you" &= groupname "Server options"
  , restrictTo     = def &= explicit &= name "r" &= name "restrictTo"
                         &= help "Accept traffic to be forwarded only to this service" &= typ "HOST:PORT"
  , verbose        = def &= groupname "Common options" &= help "Print debug information"
  , quiet          = def &= help "Print only errors"
  } &= summary (   "Use the websockets protocol to tunnel {TCP,UDP} traffic\n"
                ++ "wsTunnelClient <---> wsTunnelServer <---> RemoteHost\n"
                ++ "Use secure connection (wss://) to bypass proxies"
               )
    &= helpArg [explicit, name "help", name "h"]


toPort :: String -> Int
toPort str = case readMay str of
                  Just por -> por
                  Nothing  -> error $ "Invalid port number `" ++ str ++ "`"

parseServerInfo :: WsServerInfo -> String -> WsServerInfo
parseServerInfo server []                           = server
parseServerInfo server ('w':'s':':':'/':'/':xs)     = parseServerInfo (server {Main.useTls = False, Main.port = 80}) xs
parseServerInfo server ('w':'s':'s':':':'/':'/':xs) = parseServerInfo (server {Main.useTls = True, Main.port = 443}) xs
parseServerInfo server (':':prt)                    = server {Main.port = toPort prt}
parseServerInfo server hostPath                     = parseServerInfo (server {Main.host = takeWhile (/= ':') hostPath}) (dropWhile (/= ':') hostPath)


parseTunnelInfo :: String -> TunnelInfo
parseTunnelInfo str = mk $ BC.unpack <$> BC.split ':' (BC.pack str)
  where
    mk [lPort, host, rPort]     = TunnelInfo {localHost = "127.0.0.1", Main.localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mk [bind,lPort, host,rPort] = TunnelInfo {localHost = bind, Main.localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mk _                        = error $  "Invalid tunneling information `" ++ str ++ "`, please use format [BIND:]PORT:HOST:PORT"


parseRestrictTo :: String -> ((ByteString, Int) -> Bool)
parseRestrictTo "" = const True
parseRestrictTo str = let (!h, !p) = fromMaybe (error "Invalid Parameter restart") parse
  in (\(!hst, !port) -> hst == h && port == p)
  where
    parse = do
              let ret = BC.unpack <$> BC.split ':' (BC.pack str)
              guard (length ret == 2)
              portNumber <- readMay $ ret !! 1 :: Maybe Int
              return (BC.pack (head ret), portNumber)

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


main :: IO ()
main = do
  args <- getArgs
  cfg <- if null args then withArgs ["--help"] (cmdArgs cmdLine) else cmdArgs cmdLine

  let serverInfo = parseServerInfo (WsServerInfo False "" 0) (wsTunnelServer cfg)
  Logger.init (if quiet cfg then Logger.QUIET
                            else if verbose cfg
                            then Logger.VERBOSE
                            else Logger.NORMAL)


  if serverMode cfg
    then putStrLn ("Starting server with opts " <> tshow serverInfo )
         >> runServer (Main.useTls serverInfo) (Main.host serverInfo, fromIntegral $ Main.port serverInfo) (parseRestrictTo $ restrictTo cfg)
  else if not $ null (localToRemote cfg)
    then let (TunnelInfo lHost lPort rHost rPort) = parseTunnelInfo (localToRemote cfg)
         in runClient TunnelSettings { localBind = lHost
                                      , Types.localPort = fromIntegral lPort
                                      , serverHost = Main.host serverInfo
                                      , serverPort = fromIntegral $ Main.port serverInfo
                                      , destHost = rHost
                                      , destPort = fromIntegral rPort
                                      , Types.useTls = Main.useTls serverInfo
                                      , protocol = if udpMode cfg then UDP else TCP
                                      , proxySetting = parseProxyInfo (proxy cfg)
                                      , useSocks = False
                                      }
  else if not $ null (dynamicToRemote cfg)
    then let (TunnelInfo lHost lPort _ _) = parseTunnelInfo $ (dynamicToRemote cfg) ++ ":127.0.0.1:1212"
         in runClient TunnelSettings {  localBind = lHost
                                      , Types.localPort = fromIntegral lPort
                                      , serverHost = Main.host serverInfo
                                      , serverPort = fromIntegral $ Main.port serverInfo
                                      , destHost = ""
                                      , destPort = 0
                                      , Types.useTls = Main.useTls serverInfo
                                      , protocol = SOCKS5
                                      , proxySetting = parseProxyInfo (proxy cfg)
                                      , useSocks = True
                                      }
  else return ()


  putStrLn "Goodbye !"
  return ()
