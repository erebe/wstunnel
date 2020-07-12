{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StrictData         #-}

module Types where


import           ClassyPrelude
import           Data.Maybe
import           System.IO (stdin, stdout)
import           Data.ByteString (hGetSome, hPutStr)

import qualified Data.Streaming.Network        as N
import qualified Network.Connection            as NC
import           Network.Socket                (HostName, PortNumber)
import qualified Network.Socket                as N hiding (recv, recvFrom,
                                                     send, sendTo)
import qualified Network.Socket.ByteString     as N

import qualified Network.WebSockets.Connection as WS
import                  System.IO.Unsafe (unsafeDupablePerformIO)


instance Hashable PortNumber where
  hashWithSalt s p      = hashWithSalt s (fromEnum p)
  
deriving instance Generic N.SockAddr
deriving instance Hashable N.SockAddr


{-# NOINLINE defaultRecvBufferSize #-}   
defaultRecvBufferSize ::  Int
defaultRecvBufferSize = unsafeDupablePerformIO $
  bracket (N.socket N.AF_INET N.Stream 0) N.close (\sock -> N.getSocketOption  sock N.RecvBuffer)

defaultSendBufferSize :: Int
defaultSendBufferSize = defaultRecvBufferSize

sO_MARK :: N.SocketOption
sO_MARK = N.CustomSockOpt (1, 36) -- https://elixir.bootlin.com/linux/latest/source/arch/alpha/include/uapi/asm/socket.h#L64

{-# NOINLINE sO_MARK_Value #-}
sO_MARK_Value :: IORef Int
sO_MARK_Value = unsafeDupablePerformIO $ (newIORef 0)

data Protocol = UDP | TCP | STDIO | SOCKS5 deriving (Show, Read, Eq)

data StdioAppData = StdioAppData

data UdpAppData = UdpAppData
  { appAddr  :: N.SockAddr
  , appSem   :: MVar ByteString
  , appRead  :: IO ByteString
  , appWrite :: ByteString -> IO ()
  }

instance N.HasReadWrite UdpAppData where
  readLens f appData =  fmap (\getData -> appData { appRead = getData})  (f $ appRead appData)
  writeLens f appData = fmap (\writeData -> appData { appWrite = writeData}) (f $ appWrite appData)

data ProxySettings = ProxySettings
  { host        :: HostName
  , port        :: PortNumber
  , credentials :: Maybe (ByteString, ByteString)
  } deriving (Show)

data TunnelSettings = TunnelSettings
  { proxySetting  :: Maybe ProxySettings
  , localBind     :: HostName
  , localPort     :: PortNumber
  , serverHost    :: HostName
  , serverPort    :: PortNumber
  , destHost      :: HostName
  , destPort      :: PortNumber
  , protocol      :: Protocol
  , useTls        :: Bool
  , useSocks      :: Bool
  , upgradePrefix :: String
  , udpTimeout    :: Int
  }

instance Show TunnelSettings where
  show TunnelSettings{..} =  localBind <> ":" <> show localPort
                             <> (if isNothing proxySetting
                                 then mempty
                                 else " <==PROXY==> " <> host (fromJust proxySetting) <> ":" <> (show . port $ fromJust proxySetting)
                                )
                             <> " <==" <> (if useTls then "WSS" else "WS") <> "==> "
                             <> serverHost <> ":" <> show serverPort
                             <> " <==" <>  show (if protocol == SOCKS5 then TCP else protocol) <> "==> " <> destHost <> ":" <> show destPort


data Connection = Connection
  { read          :: IO (Maybe ByteString)
  , write         :: ByteString -> IO ()
  , close         :: IO ()
  , rawConnection :: Maybe N.Socket
  }

class ToConnection a where
  toConnection :: a -> Connection

instance ToConnection StdioAppData where
  toConnection conn = Connection { read = Just <$> hGetSome stdin 512
                                 , write = hPutStr stdout
                                 , close = return ()
                                 , rawConnection = Nothing
                                 }

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

data Error = ProxyConnectionError String
           | ProxyForwardError String
           | LocalServerError String
           | TunnelError String
           | WebsocketError String
           | TlsError String
           | Other String
           deriving (Show)
