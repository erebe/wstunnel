{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           Tunnel

import           ClassyPrelude          (ByteString, guard, readMay)
import qualified Data.ByteString.Char8  as BC
import           Data.Maybe             (fromMaybe)
import           System.Console.CmdArgs
import           System.Environment     (getArgs, withArgs)
import qualified System.Log.Logger as LOG

data WsTunnel = WsTunnel
  { localToRemote  :: String
  -- , remoteToLocal  :: String
  , wsTunnelServer :: String
  , udpMode        :: Bool
  , proxy          :: String
  , serverMode     :: Bool
  , restrictTo     :: String
  , _last          :: Bool
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
                         &= help "Listen on local and forward traffic from remote" &= groupname "Client options"
  -- , remoteToLocal  = def &= explicit &= name "R" &= name "RemoteToLocal" &= typ "[BIND:]PORT:HOST:PORT"
  --                        &= help "Listen on remote and forward traffic from local"
  , udpMode        = def &= explicit &= name "u" &= name "udp" &= help "forward UDP traffic instead of TCP"
  , proxy          = def &= explicit &= name "p" &= name "httpProxy"
                         &= help "If set, will use this proxy to connect to the server" &= typ "HOST:PORT"
  , wsTunnelServer = def &= argPos 0 &= typ "ws[s]://wstunnelServer[:port]"

  , serverMode     = def &= explicit &= name "server"
                         &= help "Start a server that will forward traffic for you" &= groupname "Server options"
  , restrictTo     = def &= explicit &= name "r" &= name "restrictTo"
                         &= help "Accept traffic to be forwarded only to this service" &= typ "HOST:PORT"
  , _last          = def &= explicit &= name "ツ" &= groupname "Common options"
  } &= summary (   "Use the websockets protocol to tunnel {TCP,UDP} traffic\n"
                ++ "wsTunnelClient <---> wsTunnelServer <---> RemoteHost\n"
                ++ "Use secure connection (wss://) to bypass proxies"
               )
    &= helpArg [explicit, name "help", name "h"]


toPort :: String -> Int
toPort str = case readMay str of
                  Just por -> por
                  Nothing -> error $ "Invalid port number `" ++ str ++ "`"

parseServerInfo :: WsServerInfo -> String -> WsServerInfo
parseServerInfo server []                           = server
parseServerInfo server ('w':'s':':':'/':'/':xs)     = parseServerInfo (server {Main.useTls = False, port = 80}) xs
parseServerInfo server ('w':'s':'s':':':'/':'/':xs) = parseServerInfo (server {Main.useTls = True, port = 443}) xs
parseServerInfo server (':':prt)                    = server {port = toPort prt}
parseServerInfo server hostPath                     = parseServerInfo (server {host = takeWhile (/= ':') hostPath}) (dropWhile (/= ':') hostPath)


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

parseProxyInfo :: String -> Maybe (String, Int)
parseProxyInfo str = do
  let ret = BC.unpack <$> BC.split ':' (BC.pack str)
  guard (length ret == 2)
  portNumber <- readMay $ ret !! 1 :: Maybe Int
  return (head ret, portNumber)

main :: IO ()
main = do
  args <- getArgs
  cfg <- if null args then withArgs ["--help"] (cmdArgs cmdLine) else cmdArgs cmdLine

  let serverInfo = parseServerInfo (WsServerInfo False "" 0) (wsTunnelServer cfg)
  LOG.updateGlobalLogger "wstunnel" (LOG.setLevel LOG.INFO)


  if serverMode cfg
    then putStrLn ("Starting server with opts " ++ show serverInfo )
         >> runServer (Main.useTls serverInfo) (host serverInfo, fromIntegral $ port serverInfo) (parseRestrictTo $ restrictTo cfg)
    else if not $ null (localToRemote cfg)
               then let (TunnelInfo lHost lPort rHost rPort) = parseTunnelInfo (localToRemote cfg)
                    in runClient TunnelSettings { localBind = lHost
                                                , Tunnel.localPort = fromIntegral lPort
                                                , serverHost = host serverInfo
                                                , serverPort = fromIntegral $ port serverInfo
                                                , destHost = rHost
                                                , destPort = fromIntegral rPort
                                                , Tunnel.useTls = Main.useTls serverInfo
                                                , protocol = if udpMode cfg then UDP else TCP
                                                , proxySetting = (\(h, p) -> (h, fromIntegral p)) <$> parseProxyInfo (proxy cfg)
                                                }
               else return ()


  putStrLn "Goodbye !"
  return ()
