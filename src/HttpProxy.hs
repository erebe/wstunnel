{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE ViewPatterns          #-}

module HttpProxy () where



import           ClassyPrelude
import qualified Data.ByteString.Char8     as BC

import           Control.Monad.Except
import qualified Data.Conduit.Network.TLS  as N
import qualified Data.Streaming.Network    as N
import           System.Timeout

import qualified Data.ByteString.Base64    as B64
import           Network.Socket            (HostName, PortNumber)
import qualified Network.Socket            as N hiding (recv, recvFrom, send,
                                                 sendTo)
import qualified Network.Socket.ByteString as N

import           Logger
import           Types


data HttpProxySettings = HttpProxySettings
  { proxyHost   :: HostName
  , proxyPort   :: PortNumber
  , credentials :: Maybe (ByteString, ByteString)
  } deriving (Show)


httpProxyConnection :: MonadError Error m => HttpProxySettings -> (HostName, PortNumber) ->  (Connection -> IO (m a)) -> IO (m a)
httpProxyConnection HttpProxySettings{..} (host, port) app = onError $ do
  debug $ "Oppening tcp connection to proxy " <> show proxyHost <> ":" <> show proxyPort

  ret <- N.runTCPClient (N.clientSettingsTCP (fromIntegral proxyPort) (fromString proxyHost)) $ \conn' -> do
    let conn = toConnection conn'
    _ <- sendConnectRequest conn

    -- wait 10sec for a reply before giving up
    let _10sec = 1000000 * 10
    responseM <- timeout _10sec $ readConnectResponse mempty conn

    case responseM of
      Just (isAuthorized -> True) -> app conn
      Just response               -> return . throwError $ ProxyForwardError (BC.unpack response)
      Nothing                     -> return . throwError $ ProxyForwardError ("No response from the proxy after "
                                                                              <> show (_10sec `div` 1000000) <> "sec" )

  debug $ "Closing tcp connection to proxy " <> show proxyHost <> ":" <> show proxyPort
  return ret

  where
    credentialsToHeader :: (ByteString, ByteString) -> ByteString
    credentialsToHeader (user, password) = "Proxy-Authorization: Basic " <> B64.encode (user <> ":" <> password) <> "\r\n"

    sendConnectRequest :: Connection -> IO ()
    sendConnectRequest h = write h $ "CONNECT " <> fromString host <> ":" <> fromString (show port) <> " HTTP/1.0\r\n"
                                  <> "Host: " <> fromString host <> ":" <> (fromString $ show port) <> "\r\n"
                                  <> maybe mempty credentialsToHeader credentials
                                  <> "\r\n"

    readConnectResponse :: ByteString -> Connection -> IO ByteString
    readConnectResponse buff conn = do
      responseM <- read conn
      case responseM of
        Nothing       -> return buff
        Just response -> if "\r\n\r\n" `isInfixOf` response
                          then return $ buff <> response
                          else readConnectResponse (buff <> response) conn

    isAuthorized :: ByteString -> Bool
    isAuthorized response = " 200 " `isInfixOf` response

    onError f = catch f $ \(e :: SomeException) -> return $
      if (take 10 (show e) == "user error")
        then throwError $ ProxyConnectionError (show e)
        else throwError $ ProxyConnectionError ("Unknown Error :: " <> show e)
