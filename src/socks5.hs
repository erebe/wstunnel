{-# LANGUAGE DeriveAnyClass        #-}
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
import           Data.Binary.Put
import qualified Data.ByteString       as BC
import qualified Data.ByteString.Char8 as BC8
import           Data.Either
import qualified Data.Text             as T
import qualified Data.Text.Encoding    as E
import           Network.Socket        (HostName, PortNumber)
import           Numeric               (showHex)

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
    sequence_ (put <$> methods)
    -- Check length <= 255

  get = do
    version <- fromIntegral <$> getWord8
    guard (version == 0x05)
    nbMethods <- fromIntegral <$> getWord8
    guard (nbMethods > 0 && nbMethods <= 0xFF)
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
             deriving (Show, Eq, Enum, Bounded)


instance Binary Command where
  put = putWord8 . (+1) . fromIntegral . fromEnum

  get = do
    cmd <- (\val -> fromIntegral val - 1) <$> getWord8
    guard $ cmd >= fromEnum (minBound :: Command) && cmd <= fromEnum (maxBound :: Command)

    return .toEnum $ cmd


instance Binary Request where
  put Request{..} = do
    putWord8 (fromIntegral version)
    put command
    putWord8 0x00 -- RESERVED
    putWord8 0x03 -- DOMAINNAME
    let host = BC8.pack addr
    putWord8 (fromIntegral . length $ host)
    traverse_ put host
    putWord16be (fromIntegral port)



  get = do
    version <- fromIntegral <$> getWord8
    guard (version == 5)
    cmd <- get :: Get Command
    _ <- getWord8 -- RESERVED

    opCode <- fromIntegral <$> getWord8 -- DOMAINNAME
    guard (opCode == 0x03)

    length <- fromIntegral <$> getWord8
    host <- either (const T.empty) id . E.decodeUtf8' <$> replicateM length getWord8
    guard (not $ null host)

    port <- fromIntegral <$> getWord16be

    return Request
      { version = version
      , command = cmd
      , addr = unpack host
      , port = port
      }



toHex :: LByteString -> String
toHex = foldr showHex "" . unpack

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
