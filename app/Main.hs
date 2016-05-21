{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           Lib

import           ClassyPrelude          (ByteString, guard, readMay)
import qualified Data.ByteString.Char8  as BC
import           Data.Maybe             (fromMaybe)
import           System.Console.CmdArgs
import           System.Environment     (getArgs, withArgs)

data WsTunnel = WsTunnel
  { localToRemote  :: String
  , remoteToLocal  :: String
  , wsTunnelServer :: String
  , udpMode        :: Bool
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
  , remoteToLocal  = def &= explicit &= name "R" &= name "RemoteToLocal" &= typ "[BIND:]PORT:HOST:PORT"
                         &= help "Listen on remote and forward traffic from local"
  , udpMode        = def &= explicit &= name "u" &= name "udp" &= help "forward UDP traffic instead of TCP"
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
parseServerInfo server ('w':'s':':':'/':'/':xs)     = parseServerInfo (server {useTls = False, port = 80}) xs
parseServerInfo server ('w':'s':'s':':':'/':'/':xs) = parseServerInfo (server {useTls = True, port = 443}) xs
parseServerInfo server (':':prt)                    = server {port = toPort prt}
parseServerInfo server hostPath                     = parseServerInfo (server {host = takeWhile (/= ':') hostPath}) (dropWhile (/= ':') hostPath)


parseTunnelInfo :: String -> TunnelInfo
parseTunnelInfo str = mk $ BC.unpack <$> BC.split ':' (BC.pack str)
  where
    mk [lPort, host, rPort]     = TunnelInfo {localHost = "127.0.0.1", localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mk [bind,lPort, host,rPort] = TunnelInfo {localHost = bind, localPort = toPort lPort, remoteHost = host, remotePort = toPort rPort}
    mk _                        = error $  "Invalid tunneling information `" ++ str ++ "`, please use format [BIND:]PORT:HOST:PORT"


parseRestrictTo :: String -> ((ByteString, Int)-> Bool)
parseRestrictTo "" = const True
parseRestrictTo str = let (!h, !p) = fromMaybe (error "Invalid Parameter restart") parse
  in (\(!hst, !port) -> hst == h && port == p)
  where
    parse = do
              let ret = BC.unpack <$> BC.split ':' (BC.pack str)
              guard (length ret == 2)
              portNumber <- readMay $ ret !! 1 :: Maybe Int
              return (BC.pack (head ret), portNumber)

main :: IO ()
main = do
  args <- getArgs
  cfg <- if null args then withArgs ["--help"] (cmdArgs cmdLine) else cmdArgs cmdLine

  let serverInfo = parseServerInfo (WsServerInfo False "" 0) (wsTunnelServer cfg)


  if serverMode cfg
    then putStrLn ("Starting server with opts " ++ show serverInfo )
         >> runServer (useTls serverInfo) (host serverInfo, fromIntegral $ port serverInfo) (parseRestrictTo $ restrictTo cfg)
    else if not $ null (localToRemote cfg)
               then let (TunnelInfo lHost lPort rHost rPort) = parseTunnelInfo (localToRemote cfg)
                    in runClient (useTls serverInfo) (if udpMode cfg then UDP else TCP) (lHost, (fromIntegral lPort))
                       (host serverInfo, fromIntegral $ port serverInfo) (rHost, (fromIntegral rPort))
               else return ()


  putStrLn "Goodbye !"
  return ()
