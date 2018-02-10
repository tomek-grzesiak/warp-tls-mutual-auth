

{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Applicative
import           Data.ASN1.Types.String      (asn1CharacterToString)
import           Data.ByteString             as BS hiding (elem)
import           Data.Default.Class          (def)
import           Data.List                   (head)
import           Data.Maybe
import           Data.X509                   (Certificate,
                                              CertificateChain (..),
                                              DistinguishedName, DnElement (..),
                                              HashALG (HashSHA256),
                                              certSubjectDN, getCertificate,
                                              getDnElement)
import           Data.X509.CertificateStore  (CertificateStore, findCertificate,
                                              readCertificateStore)
import           Data.X509.Validation        (FailedReason (..), checkLeafV3,
                                              defaultChecks, validate)
import           Network.HTTP.Types          (status200)
import           Network.TLS                 (CertificateRejectReason (..),
                                              CertificateUsage (..),
                                              ServerHooks, onClientCertificate)
import           Network.Wai                 (responseLBS)
import           Network.Wai.Handler.Warp    (defaultSettings)
import           Network.Wai.Handler.WarpTLS (TLSSettings, certFile,
                                              defaultTlsSettings, keyFile,
                                              runTLS, tlsServerHooks,
                                              tlsWantClientCert)

application _ respond = respond $
  responseLBS status200 [("Content-Type", "text/plain")] "Hello World"

main = runTLS myTlsSettings defaultSettings application

myTlsSettings :: TLSSettings
myTlsSettings = defaultTlsSettings {
    certFile = "../certs/combo.pem"
  , keyFile = "../certs/server.key"
  , tlsWantClientCert = True
  , tlsServerHooks = myDefaultServerHooks
}

openCertStore = readCertificateStore $ certFile myTlsSettings

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l   = CertificateUsageReject   CertificateRejectExpired
    | InFuture `elem` l  = CertificateUsageReject   CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject   CertificateRejectUnknownCA
    | otherwise          = CertificateUsageReject $ CertificateRejectOther (show l)

onClientCertificateHook :: CertificateChain -> IO CertificateUsage
onClientCertificateHook certChain = do
                            store <- openCertStore
                            let validationResult = liftA3 validateCert store (clientCN certChain) (Just certChain)
                            let findInTrustStore = store >>= findCert (clientDistinguishedName certChain)
                            getResult validationResult findInTrustStore
                              where getResult (Just x) (Just _) = x
                                    getResult _ Nothing =  return (CertificateUsageReject $ CertificateRejectOther "certificate unknow")
                                    getResult Nothing _ =  return (CertificateUsageReject $ CertificateRejectOther "certificate validation")

myDefaultChecks = defaultChecks {
    checkLeafV3 = False
}

type CommonName = String

validateCert :: CertificateStore -> CommonName -> CertificateChain -> IO CertificateUsage
validateCert store cName certChain= wrapCertificateChecks <$> validate HashSHA256 def myDefaultChecks store def (cName,BS.empty) certChain


clientDistinguishedName :: CertificateChain -> DistinguishedName
clientDistinguishedName (CertificateChain x) =  (certSubjectDN . getCertificate . Data.List.head) x

findCert :: DistinguishedName -> CertificateStore -> Maybe Certificate
findCert dn store = getCertificate <$> findCertificate dn store

clientCN :: CertificateChain -> Maybe CommonName
clientCN (CertificateChain x) =  (getDnElement DnCommonName . certSubjectDN . getCertificate . Data.List.head) x >>= asn1CharacterToString


myDefaultServerHooks :: ServerHooks
myDefaultServerHooks = def {
    onClientCertificate    =  onClientCertificateHook
}
