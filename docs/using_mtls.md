# Using mTLS with wstunnel

## Generating keys and certificates

WARNING: The following instructions are intended for using in a development / testing environment. They are **not**
intended for setting up a production environment. In a production environment you could use a solution such
as [OpenBao](https://openbao.org/) (opensource fork of Hashicorp Vault), [EJBCA](https://www.ejbca.org/)
or [Dogtag PKI](https://www.dogtagpki.org/) for example.

These steps are based on: https://jamielinux.com/docs/openssl-certificate-authority/

In order to setup wstunnel to authenticate clients with certificates (mTLS) one must have a certificate authority for
signing client certificates. In this example we will create a certificate authority using OpenSSL.

Run these commands from a directory which we will use to store the CA's files. For example under `~/wstunnel/client_ca`

```shell
$ mkdir -p $HOME/wstunnel/ca/{certs,csr,crl,newcerts,private}
$ cd $HOME/wstunnel/ca/
$ echo 1000 > serial
$ touch index.txt
```

Create the OpenSSL CA configuration. Beware some entries are escaped so they can be easily written out with `cat`:

```shell
$ cat > ./openssl.cnf << END_OF_FILE
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/wstunnel/ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ req ]
# Configuration for a certificate signing request.
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256
# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = wstunnel development
#organizationalUnitName_default =
#emailAddress_default           =

[ v3_ca ]
# Configuration for a certificate authority.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ client_cert ]
# Configuration for client certificates.
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Configuration for server certificates.
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Configuration for CRLs.
authorityKeyIdentifier=keyid:always
END_OF_FILE
```

Generate the private key of the certificate authority. Normally you would encrypt it and set a passphrase on it but for
development purposes we will leave it unencrypted.

```shell
$ cd $HOME/wstunnel/ca/
$ openssl genrsa -out private/ca.key.pem 4096
```

The certificate of the root certificate authority is self-signed (since it is the root of trust):

```shell
$ openssl req -config openssl.cnf \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/ca.cert.pem
---8<------
Country Name (2 letter code) [GB]:
State or Province Name [England]:
Locality Name []:
Organization Name [Alice Ltd]:
Organizational Unit Name []:
Common Name []:wstunnel Development Root CA
Email Address []:
```

Generate a key for the wstunnel server, generate a certificate signing request (CSR) and create a certificate with our
CA for the CSR:

```shell
$ openssl genrsa -out private/wstunnel-server.pem 2048
$ openssl req -config openssl.cnf \
      -key private/wstunnel-server.pem \
      -new -sha256 -out csr/wstunnel-server.csr.pem
---8<------
Country Name (2 letter code) [GB]:
State or Province Name [England]:
Locality Name []:
Organization Name [Alice Ltd]:
Organizational Unit Name []:
Common Name []:wstunnel Development Server
Email Address []:

$ openssl ca -config openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in csr/wstunnel-server.csr.pem \
      -out certs/wstunnel-server.cert.pem
---8<------
Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y
```

Next we do the same thing (generate key, create request, sign request) but then for a wstunnel client:

```shell
$ openssl genrsa -out private/wstunnel-client-1.pem 2048
$ openssl req -config openssl.cnf \
      -key private/wstunnel-client-1.pem \
      -new -sha256 -out csr/wstunnel-client-1.csr.pem
---8<------
Country Name (2 letter code) [GB]:
State or Province Name [England]:
Locality Name []:
Organization Name [Alice Ltd]:
Organizational Unit Name []:
Common Name []:wstunnel_client_1   # must contains only url valid characters
Email Address []:

$ openssl ca -config openssl.cnf \
      -extensions client_cert -days 375 -notext -md sha256 \
      -in csr/wstunnel-client-1.csr.pem \
      -out certs/wstunnel-client-1.cert.pem
---8<------
Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y
```

## Using mTLS on the wstunnel server side

This section assumes you have generated the certificate authority, keys, certificates, etc. as outlined in the "
Generating keys and certificates" section.

Start a `wstunnel` server and make it use the server key pair certificate (`--tls-certificate` and `--tls-private-key`)
and configure it to authenticate clients via mTLS (`--tls-client-ca-certs`):

```shell
$ wstunnel server \
   --tls-certificate ./certs/wstunnel-server.cert.pem \
   --tls-private-key ./private/wstunnel-server.pem \
   --tls-client-ca-certs ./certs/ca.cert.pem \
   wss://0.0.0.0:8443
```

### Testing

You can use `openssl` to test connecting with the client certificate to the wstunnel server:

```shell
$ openssl s_client -connect 127.0.0.1:8443 \
   -key ./private/wstunnel-client-1.pem \
   -cert ./certs/wstunnel-client-1.cert.pem \
   -cert_chain ./certs/ca.cert.pem \
   -state -debug
---8<-----
Acceptable client certificate CA names
C = GB, ST = England, O = Alice Ltd, CN = wstunnel Development Root CA
---8<-----
```

Similarly, you can use `openssl` to test what happens if you try to connect with a client certificate which is not
signed by our CA by generating a self-signed certificate:

```shell
$ openssl req -nodes -x509 -sha256 -newkey rsa:4096 \
  -keyout faux.key.pem \
  -out faux.crt.pem \
  -days 356 \
  -subj "/C=GB/ST=England/L=London/O=ACME Corp/OU=IT Dept/CN=Development Faux Client"
$ openssl s_client -connect 127.0.0.1:8443 \
   -key faux.key.pem \
   -cert faux.crt.pem \
   -cert_chain ./certs/ca.cert.pem \
   -state -debug
----8<----
SSL3 alert read:fatal:certificate unknown
---8<-----
```

Trying to connect without the client presenting any certificate at all will also fail (the `--cacert` flag only
tells `curl` which CA certificate to use to verify the certificate of the **server** with):

```shell
$ curl -vvv --cacert ./certs/ca.cert.pem https://127.0.0.1:8443
```

## Using mTLS on the wstunnel client side

This section assumes you have generated the certificate authority, keys, certificates, etc. as outlined in the "
Generating keys and certificates" section. It also assumes you have a running wstunnel server with mTLS configured. For
example as setup in the `Using mTLS on the wstunnel server side` section.

```shell
$ wstunnel client \
   --tls-certificate ./certs/wstunnel-client-1.cert.pem \
   --tls-private-key ./private/wstunnel-client-1.pem \
   -L tcp://1212:localhost:1313 \
   wss://127.0.0.1:8443
   
 $ nc 127.0.0.1 1212
```

