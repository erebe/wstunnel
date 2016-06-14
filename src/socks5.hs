{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NoImplicitPrelude     #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}

module Socks5 where


import           ClassyPrelude
import qualified Data.Binary.Get as Bin
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
