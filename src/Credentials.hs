{-# LANGUAGE OverloadedStrings #-}

module Credentials where

import           ClassyPrelude

-- openssl genrsa 512 > host.key
-- openssl req -new -x509 -nodes -sha1 -days 9999 -key host.key > host.cert
key :: ByteString
key = "-----BEGIN RSA PRIVATE KEY-----\n" <>
  "MIIBOgIBAAJBAMEEloIcF3sTGYhQmybyDm1NOpXmf94rR1fOwENjuW6jh4WTaz5k\n" <>
  "Uew8CR58e7c5GgK08ZOJwi2Hpl9MfDm4mGUCAwEAAQJAGP+nHqLUx7PpkqYd8iVX\n" <>
  "iQB/nfqEhRnF27GDZTb9RT7e3bR7X1B9oIBnpmqwMG5oPxidoIKv+jzZjsQcxKLu\n" <>
  "4QIhAPdcPmFrtLUpTXx21wtVxotsO7+YcQxtRtBoXeiREUInAiEAx8Jx9a6eVRIh\n" <>
  "slSTJMPuy/LbvK8VUTqtx9x2EhFhBJMCIQC68qlmwZs6y/N3HO4b8AD1gKCLhm/y\n" <>
  "P2ikvCw1R+ZuQwIgdfcgMUPzgK16dMN5OabzaEF8/kouvo92fKZ2m2jj8D0CIFY8\n" <>
  "4SkXDkpeUEKKfxHqrEkkxmpRk93Ui1NPyN+wxrgO\n" <>
  "-----END RSA PRIVATE KEY-----"

certificate :: ByteString
certificate = "-----BEGIN CERTIFICATE-----\n" <>
  "MIICXTCCAgegAwIBAgIJAJf1Sm7DI0KcMA0GCSqGSIb3DQEBBQUAMIGJMQswCQYD\n" <>
  "VQQGEwJGUjESMBAGA1UECAwJQXF1aXRhaW5lMRAwDgYDVQQHDAdCYXlvbm5lMQ4w\n" <>
  "DAYDVQQKDAVFcmViZTELMAkGA1UECwwCSVQxFjAUBgNVBAMMDXJvbWFpbi5nZXJh\n" <>
  "cmQxHzAdBgkqhkiG9w0BCQEWEHdoeW5vdEBnbWFpbC5jb20wHhcNMTYwNTIxMTUy\n" <>
  "MzIyWhcNNDMxMDA2MTUyMzIyWjCBiTELMAkGA1UEBhMCRlIxEjAQBgNVBAgMCUFx\n" <>
  "dWl0YWluZTEQMA4GA1UEBwwHQmF5b25uZTEOMAwGA1UECgwFRXJlYmUxCzAJBgNV\n" <>
  "BAsMAklUMRYwFAYDVQQDDA1yb21haW4uZ2VyYXJkMR8wHQYJKoZIhvcNAQkBFhB3\n" <>
  "aHlub3RAZ21haWwuY29tMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMEEloIcF3sT\n" <>
  "GYhQmybyDm1NOpXmf94rR1fOwENjuW6jh4WTaz5kUew8CR58e7c5GgK08ZOJwi2H\n" <>
  "pl9MfDm4mGUCAwEAAaNQME4wHQYDVR0OBBYEFLY0HsQst1t3QRXU0aTWg3V1IvGX\n" <>
  "MB8GA1UdIwQYMBaAFLY0HsQst1t3QRXU0aTWg3V1IvGXMAwGA1UdEwQFMAMBAf8w\n" <>
  "DQYJKoZIhvcNAQEFBQADQQCP4oYOIrX7xvmQih3hvF4kUnbKjtttImdGruonsLAz\n" <>
  "OL2VExC6OqlDP2yu14BlsjTt+X2v6mhHnSM16c6AkpM/\n" <>
  "-----END CERTIFICATE-----"
