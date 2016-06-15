{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NoImplicitPrelude     #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}

module Socks5 where


import           ClassyPrelude
import           Data.Binary
import           Data.Binary.Get
import           Network.Socket  (HostName, PortNumber)

data AuthMethod = NoAuth
                | GSSAPI
                | Login
                | Reserved
                | NotAllowed
                deriving (Show, Read)

data RequestAuth = RequestAuth
  { version :: Int
  , methods :: Vector AuthMethod
  } deriving (Show, Read)

instance Binary AuthMethod where
  put val = case val of
    NoAuth -> putWord8 0x00
    GSSAPI -> putWord8 0x01
    Login -> putWord8 0x02
    NotAllowed -> putWord8 0xFF
    _ {- Reserverd -} -> putWord8 0x03

  get = do
    method <- getWord8
    return $ case method of
      0x00 -> NoAuth
      0x01 -> GSSAPI
      0x02 -> Login
      0xFF -> NotAllowed
      _ -> Reserved


instance Binary RequestAuth where
  put RequestAuth{..} = do
    putWord8 (fromIntegral version)
    putWord8 (fromIntegral $ length methods)
    sequence_ ( put <$> methods)

  get = do
    version <- fromIntegral <$> getWord8
    guard (version == 0x05)
    nbMethods <- fromIntegral <$> getWord8
    guard (version <= 0xFF)
    methods <- replicateM nbMethods get
    return $ RequestAuth version methods




data Request = Request
  { version :: Int
  , command :: Command
  , addr    :: HostName
  , port    :: PortNumber
  } deriving (Show)

data Command = Connect
             | Bind
             | UdpAssociate
             deriving (Show, Eq)


data Response = Response
  { version    :: Int
  , returnCode :: RetCode
  , serverAddr :: HostName
  , serverPort :: PortNumber
  } deriving (Show)

data RetCode = SUCCEEDED
             | GENERAL_FAILURE
             | NOT_ALLOWED
             | NO_NETWORK
             | HOST_UNREACHABLE
             | CONNECTION_REFUSED
             | TTL_EXPIRED
             | UNSUPPORTED_COMMAND
             | UNSUPPORTED_ADDRESS_TYPE
             deriving (Show, Eq)
