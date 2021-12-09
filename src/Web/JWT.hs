{-# LANGUAGE CPP                #-}
{-# LANGUAGE EmptyDataDecls     #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE GADTs              #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RankNTypes         #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE StandaloneDeriving #-}

{-|
Module:      Web.JWT
License:     MIT
Maintainer:  Stefan Saasen <stefan@saasen.me>
Stability:   experimental

This implementation of JWT is based on <https://tools.ietf.org/html/rfc7519>
but currently only implements the minimum required to work with the Atlassian Connect framework and GitHub App

Known limitations:

   * Only HMAC SHA-256 and RSA SHA-256 algorithms are currently a supported signature algorithm

   * There is currently no verification of time related information
   ('exp', 'nbf', 'iat').

   * Registered claims are not validated
-}
module Web.JWT
    (
    -- * Encoding & Decoding JWTs
    -- ** Decoding
    -- $docDecoding
      decode
    , verify
    , decodeAndVerifySignature
    -- ** Encoding
    , encodeSigned
    , encodeUnsigned

    -- * Utility functions
    -- ** Common
    , tokenIssuer
    , hmacSecret
    , readRsaSecret
    , readRsaPublicKey
    , toVerify
    -- ** JWT structure
    , claims
    , header
    , signature
    -- ** JWT claims set
    , auds
    , intDate
    , numericDate
    , stringOrURI
    , stringOrURIToText
    , secondsSinceEpoch

    -- * Types
    , UnverifiedJWT
    , VerifiedJWT
    , Signature
    , VerifySigner(..)
    , EncodeSigner(..)
    , JWT
    , Algorithm(..)
    , JWTClaimsSet(..)
    , ClaimsMap(..)
    , IntDate
    , NumericDate
    , StringOrURI
    , JWTHeader
    , JOSEHeader(..)

    -- * Deprecated
    , rsaKeySecret
    ) where

import           Data.Bifunctor             (first)
import qualified Data.ByteString.Char8      as C8
import qualified Data.ByteString.Lazy.Char8 as BL (fromStrict, toStrict)
import qualified Data.ByteString.Extended as BS
import qualified Data.Text.Extended         as T
import qualified Data.Text.Encoding         as TE

import           Control.Applicative
import           Control.Monad
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import           Crypto.PubKey.RSA          (PrivateKey, PublicKey)
import qualified Crypto.PubKey.RSA.PKCS15   as RSA
import           Crypto.Store.X509          (readPubKeyFileFromMemory)
import           Data.ByteArray.Encoding
import           Data.Aeson                 hiding (decode, encode)
import qualified Data.Aeson                 as JSON
import qualified Data.Map                   as Map
import           Data.Maybe
import           Data.Scientific
import qualified Data.Semigroup             as Semigroup
import           Data.Time.Clock            (NominalDiffTime)
import           Data.X509                  (PrivKey (PrivKeyRSA), PubKey (PubKeyRSA))
import           Data.X509.Memory           (readKeyFileFromMemory)
import qualified Network.URI                as URI
import           Prelude                    hiding (exp)

#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.Key             as Key
import qualified Data.Aeson.KeyMap          as KeyMap
#else
import qualified Data.HashMap.Strict        as KeyMap
#endif

-- $setup
-- The code examples in this module require GHC's `OverloadedStrings`
-- extension:
--
-- >>> :set -XOverloadedStrings

{-# DEPRECATED JWTHeader "Use JOSEHeader instead. JWTHeader will be removed in 1.0" #-}
type JWTHeader = JOSEHeader

data VerifySigner = VerifyHMACSecret BS.ByteString
                  | VerifyRSAPrivateKey PrivateKey
                  | VerifyRSAPublicKey PublicKey

data EncodeSigner = EncodeHMACSecret BS.ByteString
                  | EncodeRSAPrivateKey PrivateKey

newtype Signature = Signature T.Text deriving (Show)

instance Eq Signature where
    (Signature s1) == (Signature s2) = s1 `T.constTimeCompare` s2

-- | JSON Web Token without signature verification
data UnverifiedJWT

-- | JSON Web Token that has been successfully verified
data VerifiedJWT


-- | The JSON Web Token
data JWT r where
   Unverified :: JWTHeader -> JWTClaimsSet -> Signature -> T.Text -> JWT UnverifiedJWT
   Verified   :: JWTHeader -> JWTClaimsSet -> Signature -> JWT VerifiedJWT

deriving instance Show (JWT r)

-- | Extract the claims set from a JSON Web Token
claims :: JWT r -> JWTClaimsSet
claims (Unverified _ c _ _) = c
claims (Verified _ c _) = c

-- | Extract the header from a JSON Web Token
header :: JWT r -> JOSEHeader
header (Unverified h _ _ _) = h
header (Verified h _ _) = h

-- | Extract the signature from a verified JSON Web Token
signature :: JWT r -> Maybe Signature
signature Unverified{}     = Nothing
signature (Verified _ _ s) = Just s

-- | A JSON numeric value representing the number of seconds from
-- 1970-01-01T0:0:0Z UTC until the specified UTC date/time.
{-# DEPRECATED IntDate "Use NumericDate instead. IntDate will be removed in 1.0" #-}
type IntDate = NumericDate

-- | A JSON numeric value representing the number of seconds from
-- 1970-01-01T0:0:0Z UTC until the specified UTC date/time.
newtype NumericDate = NumericDate Integer deriving (Show, Eq, Ord)


-- | Return the seconds since 1970-01-01T0:0:0Z UTC for the given 'IntDate'
secondsSinceEpoch :: NumericDate -> NominalDiffTime
secondsSinceEpoch (NumericDate s) = fromInteger s

-- | A JSON string value, with the additional requirement that while
-- arbitrary string values MAY be used, any value containing a ":"
-- character MUST be a URI [RFC3986].  StringOrURI values are
-- compared as case-sensitive strings with no transformations or
-- canonicalizations applied.
data StringOrURI = S T.Text | U URI.URI deriving (Eq)

instance Show StringOrURI where
    show (S s) = T.unpack s
    show (U u) = show u

data Algorithm = HS256 -- ^ HMAC using SHA-256 hash algorithm
               | RS256 -- ^ RSA using SHA-256 hash algorithm
                 deriving (Eq, Show)

-- | JOSE Header, describes the cryptographic operations applied to the JWT
data JOSEHeader = JOSEHeader {
    -- | The typ (type) Header Parameter defined by [JWS] and [JWE] is used to
    -- declare the MIME Media Type [IANA.MediaTypes] of this complete JWT in
    -- contexts where this is useful to the application.
    -- This parameter has no effect upon the JWT processing.
    typ :: Maybe T.Text
    -- | The cty (content type) Header Parameter defined by [JWS] and [JWE] is
    -- used by this specification to convey structural information about the JWT.
  , cty :: Maybe T.Text
    -- | The alg (algorithm) used for signing the JWT. The HS256 (HMAC using
    -- SHA-256) is the only required algorithm in addition to "none" which means
    -- that no signature will be used.
    --
    -- See <http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#page-6>
  , alg :: Maybe Algorithm
    -- | The "kid" (key ID) Header Parameter is a hint indicating which key
    -- was used to secure the JWS.  This parameter allows originators to
    -- explicitly signal a change of key to recipients.  The structure of
    -- the "kid" value is unspecified.  Its value MUST be a case-sensitive
    -- string.  Use of this Header Parameter is OPTIONAL.
    --
    -- See <https://tools.ietf.org/html/rfc7515#section-4.1.4>
  , kid :: Maybe T.Text
} deriving (Eq, Show)

instance Monoid JOSEHeader where
    mempty =
      JOSEHeader Nothing Nothing Nothing Nothing
    mappend = (Semigroup.<>)

instance Semigroup.Semigroup JOSEHeader where
  JOSEHeader a b c d <> JOSEHeader a' b' c' d' =
    JOSEHeader (a <|> a') (b <|> b') (c <|> c') (d <|> d')

-- | The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
data JWTClaimsSet = JWTClaimsSet {
    -- Registered Claim Names
    -- http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#ClaimsContents

    -- | The iss (issuer) claim identifies the principal that issued the JWT.
    iss                :: Maybe StringOrURI

    -- | The sub (subject) claim identifies the principal that is the subject of the JWT.
  , sub                :: Maybe StringOrURI

    -- | The aud (audience) claim identifies the audiences that the JWT is intended for according to draft 18 of the JWT spec, the aud claim is option and may be present in singular or as a list.
  , aud                :: Maybe (Either StringOrURI [StringOrURI])

    -- | The exp (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Its value MUST be a number containing an IntDate value.
  , exp                :: Maybe IntDate

    -- | The nbf (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
  , nbf                :: Maybe IntDate

    -- | The iat (issued at) claim identifies the time at which the JWT was issued.
  , iat                :: Maybe IntDate

    -- | The jti (JWT ID) claim provides a unique identifier for the JWT.
  , jti                :: Maybe StringOrURI

  , unregisteredClaims :: ClaimsMap

} deriving (Show, Eq)

instance Monoid JWTClaimsSet where
  mempty =
    JWTClaimsSet Nothing Nothing Nothing Nothing Nothing Nothing Nothing $ ClaimsMap Map.empty
  mappend = (Semigroup.<>)

instance Semigroup.Semigroup JWTClaimsSet where
  JWTClaimsSet a b c d e f g h <> JWTClaimsSet a' b' c' d' e' f' g' h' =
    JWTClaimsSet (a <|> a') (b <|> b') (c <|> c') (d <|> d') (e <|> e') (f <|> f') (g <|> g') (h Semigroup.<> h')

-- | Encode a claims set using the given secret
--
--  @
--  let
--      cs = mempty { -- mempty returns a default JWTClaimsSet
--         iss = stringOrURI "Foo"
--       , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
--      }
--      key = hmacSecret "secret-key"
--  in encodeSigned key mempty cs
-- @
-- > "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0.vHQHuG3ujbnBUmEp-fSUtYxk27rLiP2hrNhxpyWhb2E"
encodeSigned :: EncodeSigner -> JOSEHeader -> JWTClaimsSet -> T.Text
encodeSigned signer header' claims' = dotted [header'', claim, signature']
    where claim     = encodeJWT claims'
          algo      = case signer of
                        EncodeHMACSecret _    -> HS256
                        EncodeRSAPrivateKey _ -> RS256

          header''  = encodeJWT header' {
                        typ = Just "JWT"
                      , alg = Just algo
                      }
          signature' = calculateDigest signer (dotted [header'', claim])

-- | Encode a claims set without signing it
--
--  @
--  let
--      cs = mempty { -- mempty returns a default JWTClaimsSet
--      iss = stringOrURI "Foo"
--    , iat = numericDate 1394700934
--    , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
--  }
--  in encodeUnsigned cs mempty
--  @
-- > "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjEzOTQ3MDA5MzQsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJGb28ifQ."
encodeUnsigned :: JWTClaimsSet -> JOSEHeader -> T.Text
encodeUnsigned claims' header' = dotted [header'', claim, ""]
    where claim     = encodeJWT claims'
          header''  = encodeJWT header' {
                        typ = Just "JWT"
                      , alg = Just HS256
                      }

-- | Decode a claims set without verifying the signature. This is useful if
-- information from the claim set is required in order to verify the claim
-- (e.g. the secret needs to be retrieved based on unverified information
-- from the claims set).
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mJwt = decode input
--  in fmap header mJwt
-- :}
-- Just (JOSEHeader {typ = Just "JWT", cty = Nothing, alg = Just HS256, kid = Nothing})
--
-- and
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mJwt = decode input
--  in fmap claims mJwt
-- :}
-- Just (JWTClaimsSet {iss = Nothing, sub = Nothing, aud = Nothing, exp = Nothing, nbf = Nothing, iat = Nothing, jti = Nothing, unregisteredClaims = ClaimsMap {unClaimsMap = fromList [("some",String "payload")]}})
decode :: T.Text -> Maybe (JWT UnverifiedJWT)
decode input = do
    (h,c,s) <- extractElems $ T.splitOn "." input
    let header' = parseJWT h
        claims' = parseJWT c
    Unverified <$> header' <*> claims' <*> (pure . Signature $ s) <*> (pure . dotted $ [h,c])
    where
        extractElems (h:c:s:_) = Just (h,c,s)
        extractElems _         = Nothing

-- | Using a known secret and a decoded claims set verify that the signature is correct
-- and return a verified JWT token as a result.
--
-- This will return a VerifiedJWT if and only if the signature can be verified using the
-- given secret.
--
-- The separation between decode and verify is very useful if you are communicating with
-- multiple different services with different secrets and it allows you to lookup the
-- correct secret for the unverified JWT before trying to verify it. If this is not an
-- isuse for you (there will only ever be one secret) then you should just use
-- 'decodeAndVerifySignature'.
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mUnverifiedJwt = decode input
--      mVerifiedJwt = verify (hmacSecret "secret") =<< mUnverifiedJwt
--  in signature =<< mVerifiedJwt
-- :}
-- Just (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U")
verify :: VerifySigner -> JWT UnverifiedJWT -> Maybe (JWT VerifiedJWT)
verify signer (Unverified header' claims' unverifiedSignature originalClaim) = do
   guard (verifyDigest signer unverifiedSignature originalClaim)
   pure $ Verified header' claims' unverifiedSignature

-- | Decode a claims set and verify that the signature matches by using the supplied secret.
-- The algorithm is based on the supplied header value.
--
-- This will return a VerifiedJWT if and only if the signature can be verified
-- using the given secret.
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mJwt = decodeAndVerifySignature (hmacSecret "secret") input
--  in signature =<< mJwt
-- :}
-- Just (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U")
decodeAndVerifySignature :: VerifySigner -> T.Text -> Maybe (JWT VerifiedJWT)
decodeAndVerifySignature signer input = verify signer =<< decode input

-- | Try to extract the value for the issue claim field 'iss' from the web token in JSON form
tokenIssuer :: T.Text -> Maybe StringOrURI
tokenIssuer = decode >=> fmap pure claims >=> iss

-- | Create a Secret using the given key.
-- Consider using `HMACSecret` instead if your key is not already a "Data.Text".
hmacSecret :: T.Text -> EncodeSigner
hmacSecret = EncodeHMACSecret . TE.encodeUtf8

-- | Converts an EncodeSigner into a VerifySigner
-- If you can encode then you can always verify; but the reverse is not always true.
toVerify :: EncodeSigner -> VerifySigner
toVerify (EncodeHMACSecret s) = VerifyHMACSecret s
toVerify (EncodeRSAPrivateKey pk) = VerifyRSAPrivateKey pk

-- | Create an RSAPrivateKey from PEM contents
--
-- Please, consider using 'readRsaSecret' instead.
rsaKeySecret :: String -> IO (Maybe EncodeSigner)
rsaKeySecret = pure . fmap EncodeRSAPrivateKey . readRsaSecret . C8.pack

-- | Create an RSA 'PrivateKey' from PEM contents
--
-- > readRsaSecret <$> BS.readFile "foo.pem"
--
-- >>> :{
--   -- A random example key created with `ssh-keygen -t rsa`
--   fromJust . readRsaSecret . C8.pack $ unlines
--       [ "-----BEGIN RSA PRIVATE KEY-----"
--       , "MIIEowIBAAKCAQEAkkmgbLluo5HommstpHr1h53uWfuN3CwYYYR6I6a2MzAHIMIv"
--       , "8Ak2ha+N2UDeYsfVhZ/DOnE+PMm2RpYSaiYT0l2a7ZkmRSbcyvVFt3XLePJbmUgo"
--       , "ieyccS4uYHeqRggdWH9His3JaR2N71N9iU0+mY5nu2+15iYw3naT/PSx01IzBqHN"
--       , "Zie1z3FYX09FgOs31mcR8VWj8DefxbKE08AW+vDMT2AmUC2b+Gqk6SqRz29HuPBs"
--       , "yyV4Xl9CgzcCWjuXTv6mevDygo5RVZg34U6L1iFRgwwHbrLcd2N97wlKz+OiDSgM"
--       , "sbZWA0i2D9ZsDR9rdEdXzUIw6toIRYZfeI9QYQIDAQABAoIBAEXkh5Fqx0G/ZLLi"
--       , "olwDo2u4OTkkxxJ6vutYsEJ4VHUAbWdpYB3/SN12kv9JzvbDI3FEc7JoiKPifAQd"
--       , "j47HwpCvyGXc1jwT5UnTBgwxa5XNtZX2s+ex9Mzek6njgqcTGXI+3Z+j0qc2R6og"
--       , "6cm/7jjPoSAcr3vWo2KmpO4muw+LbYoSGo0Jydoa5cGtkmDfsjjrMw7mDoRttdhw"
--       , "WdhS+q2aJPFI7q7itoYUd7KLe3nOeM0zd35Pc8Qc6jGk+JZxQdXrb/NrSNgAATcN"
--       , "GGS226Q444N0pAfc188IDcAtQPSJpzbs/1+TPzE4ov/lpHTr91hXr3RLyVgYBI01"
--       , "jrggfAECgYEAwaC4iDSZQ+8eUx/zR973Lu9mvQxC2BZn6QcOtBcIRBdGRlXfhwuD"
--       , "UgwVZ2M3atH5ZXFuQ7pRtJtj7KCFy7HUFAJC15RCfLjx+n39bISNp5NOJEdI+UM+"
--       , "G2xMHv5ywkULV7Jxb+tSgsYIvJ0tBjACkif8ahNjgVJmgMSOgdHR2pkCgYEAwWkN"
--       , "uquRqKekx4gx1gJYV7Y6tPWcsZpEcgSS7AGNJ4UuGZGGHdStpUoJICn2cFUngYNz"
--       , "eJXOg+VhQJMqQx9c+u85mg/tJluGaw95tBAafspwvhKewlO9OhQeVInPbXMUwrJ0"
--       , "PS3XV7c74nxm6Nn4QHlM07orn3lOiWxZF8BBSQkCgYATjwSU3ZtNvW22v9d3PxKA"
--       , "7zXVitOFuF2usEPP9TOkjSVQHYSCw6r0MrxGwULry2IB2T9mH//42mlxkZVySfg+"
--       , "PSw7UoKUzqnCv89Fku4sKzkNeRXp99ziMEJQLyuwbAEFTsUepQqkoxRm2QmfQmJA"
--       , "GUHqBSNcANLR1wj+HA+yoQKBgQCBlqj7RQ+AaGsQwiFaGhIlGtU1AEgv+4QWvRfQ"
--       , "B64TJ7neqdGp1SFP2U5J/bPASl4A+hl5Vy6a0ysZQEGV3cLH41e98SPdin+C5kiO"
--       , "LCgEghGOWR2EaOUlr+sui3OvCueDGFynzTo27G+0bdPp+nnKgTvHtTqbTIUhsLX1"
--       , "IvzbOQKBgH4q36jgBb9T3hjXtWyrytlmFtBdw0i+UiMvMlnOqujGhcnOk5UMyxOQ"
--       , "sQI+/31jIGbmlE7YaYykR1FH3LzAjO4J1+m7vv5fIRdG8+sI01xTc8UAdbmWtK+5"
--       , "TK1oLP43BHH5gRAfIlXj2qmap5lEG6If/xYB4MOs8Bui5iKaJlM5"
--       , "-----END RSA PRIVATE KEY-----"
--       ]
-- :}
-- PrivateKey {private_pub = PublicKey {public_size = 256, public_n = 1846..., public_e = 65537}, private_d = 8823..., private_p = 135..., private_q = 1358..., private_dP = 1373..., private_dQ = 9100..., private_qinv = 8859...}
--
readRsaSecret :: BS.ByteString -> Maybe PrivateKey
readRsaSecret bs =
    case readKeyFileFromMemory bs of
        [(PrivKeyRSA k)] -> Just k
        _                -> Nothing

readRsaPublicKey :: BS.ByteString -> Maybe PublicKey
readRsaPublicKey bs =
    case readPubKeyFileFromMemory bs of
          [(PubKeyRSA k)] -> Just k
          _                -> Nothing

-- | Convert the `NominalDiffTime` into an IntDate. Returns a Nothing if the
-- argument is invalid (e.g. the NominalDiffTime must be convertible into a
-- positive Integer representing the seconds since epoch).
{-# DEPRECATED intDate "Use numericDate instead. intDate will be removed in 1.0" #-}
intDate :: NominalDiffTime -> Maybe IntDate
intDate = numericDate

-- | Convert the `NominalDiffTime` into an NumericDate. Returns a Nothing if the
-- argument is invalid (e.g. the NominalDiffTime must be convertible into a
-- positive Integer representing the seconds since epoch).
numericDate :: NominalDiffTime -> Maybe NumericDate
numericDate i | i < 0 = Nothing
numericDate i         = Just $ NumericDate $ round i

-- | Convert a `T.Text` into a 'StringOrURI`. Returns a Nothing if the
-- String cannot be converted (e.g. if the String contains a ':' but is
-- *not* a valid URI).
stringOrURI :: T.Text -> Maybe StringOrURI
stringOrURI t | URI.isURI $ T.unpack t = U <$> URI.parseURI (T.unpack t)
stringOrURI t                          = Just (S t)


-- | Convert a `StringOrURI` into a `T.Text`. Returns the T.Text
-- representing the String as-is or a Text representation of the URI
-- otherwise.
stringOrURIToText :: StringOrURI -> T.Text
stringOrURIToText (S t)   = t
stringOrURIToText (U uri) = T.pack $ URI.uriToString id uri (""::String)

-- | Convert the `aud` claim in a `JWTClaimsSet` into a `[StringOrURI]`
auds :: JWTClaimsSet -> [StringOrURI]
auds jwt = case aud jwt of
    Nothing         -> []
    Just (Left a)   -> [a]
    Just (Right as) -> as

-- =================================================================================

encodeJWT :: ToJSON a => a -> T.Text
encodeJWT = TE.decodeUtf8 . convertToBase Base64URLUnpadded . BL.toStrict . JSON.encode

parseJWT :: FromJSON a => T.Text -> Maybe a
parseJWT x = case convertFromBase Base64URLUnpadded $ TE.encodeUtf8 x of
               Left _  -> Nothing
               Right s -> JSON.decode $ BL.fromStrict s

dotted :: [T.Text] -> T.Text
dotted = T.intercalate "."


-- =================================================================================

calculateDigest :: EncodeSigner -> T.Text -> T.Text
calculateDigest (EncodeHMACSecret key) msg =
    TE.decodeUtf8 $ convertToBase Base64URLUnpadded (hmac key (TE.encodeUtf8 msg) :: HMAC SHA256)

calculateDigest (EncodeRSAPrivateKey key) msg = TE.decodeUtf8
    $ convertToBase Base64URLUnpadded
    $ sign'
    $ TE.encodeUtf8 msg
  where
    sign' :: BS.ByteString -> BS.ByteString
    sign' bs = case RSA.sign Nothing (Just SHA256) key bs of
        Right sig -> sig
        Left  _   -> error "impossible"  -- This function can only fail with @SignatureTooLong@,
                                         -- which is impossible because we use a hash.

verifyDigest :: VerifySigner -> Signature -> T.Text -> Bool
verifyDigest (VerifyHMACSecret key) unverifiedSig msg = unverifiedSig == Signature (calculateDigest (EncodeHMACSecret key) msg)
verifyDigest (VerifyRSAPrivateKey pk) unverifiedSig msg = unverifiedSig == Signature (calculateDigest (EncodeRSAPrivateKey pk) msg)
verifyDigest (VerifyRSAPublicKey pk) (Signature base64Sig) msg =
  let
    decodedSig =
      convertFromBase Base64URLUnpadded (TE.encodeUtf8 base64Sig)
  in
    either (pure False) (RSA.verify (Just SHA256) pk (TE.encodeUtf8 msg)) decodedSig

-- =================================================================================

newtype ClaimsMap = ClaimsMap { unClaimsMap :: Map.Map T.Text Value }
    deriving (Eq, Show)

instance Monoid ClaimsMap where
  mempty =
    ClaimsMap mempty
  mappend = (Semigroup.<>)

instance Semigroup.Semigroup ClaimsMap where
  ClaimsMap a <> ClaimsMap b =
    ClaimsMap $ a Semigroup.<> b

fromHashMap :: Object -> ClaimsMap
fromHashMap = ClaimsMap . Map.fromList . map (first toText) . KeyMap.toList
  where
#if MIN_VERSION_aeson(2,0,0)
    toText = Key.toText
#else
    toText = id
#endif

removeRegisteredClaims :: ClaimsMap -> ClaimsMap
removeRegisteredClaims (ClaimsMap input) = ClaimsMap $ Map.differenceWithKey (\_ _ _ -> Nothing) input registeredClaims
    where
        registeredClaims = Map.fromList $ map (\e -> (e, Null)) ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

instance ToJSON JWTClaimsSet where
    toJSON JWTClaimsSet{..} = object $ catMaybes [
                  fmap ("iss" .=) iss
                , fmap ("sub" .=) sub
                , either ("aud" .=) ("aud" .=) <$> aud
                , fmap ("exp" .=) exp
                , fmap ("nbf" .=) nbf
                , fmap ("iat" .=) iat
                , fmap ("jti" .=) jti
            ] ++ map (first fromText) (Map.toList $ unClaimsMap $ removeRegisteredClaims unregisteredClaims)
      where
#if MIN_VERSION_aeson(2,0,0)
        fromText = Key.fromText
#else
        fromText = id
#endif

instance FromJSON JWTClaimsSet where
        parseJSON = withObject "JWTClaimsSet"
                     (\o -> JWTClaimsSet
                     <$> o .:? "iss"
                     <*> o .:? "sub"
                     <*> case KeyMap.lookup "aud" o of
                         (Just as@(JSON.Array _)) -> Just <$> Right <$> parseJSON as
                         (Just (JSON.String t))   -> pure $ Left <$> stringOrURI t
                         _                        -> pure Nothing
                     <*> o .:? "exp"
                     <*> o .:? "nbf"
                     <*> o .:? "iat"
                     <*> o .:? "jti"
                     <*> pure (removeRegisteredClaims $ fromHashMap o))

instance FromJSON JOSEHeader where
    parseJSON = withObject "JOSEHeader"
                    (\o -> JOSEHeader
                    <$> o .:? "typ"
                    <*> o .:? "cty"
                    <*> o .:? "alg"
                    <*> o .:? "kid")

instance ToJSON JOSEHeader where
    toJSON JOSEHeader{..} = object $ catMaybes [
                  fmap ("typ" .=) typ
                , fmap ("cty" .=) cty
                , fmap ("alg" .=) alg
                , fmap ("kid" .=) kid
            ]

instance ToJSON NumericDate where
    toJSON (NumericDate i) = Number $ scientific (fromIntegral i) 0

instance FromJSON NumericDate where
    parseJSON (Number x) = return $ NumericDate $ coefficient x
    parseJSON _          = mzero

instance ToJSON Algorithm where
    toJSON HS256 = String ("HS256"::T.Text)
    toJSON RS256 = String ("RS256"::T.Text)

instance FromJSON Algorithm where
    parseJSON (String "HS256") = return HS256
    parseJSON (String "RS256") = return RS256
    parseJSON _                = mzero

instance ToJSON StringOrURI where
    toJSON (S s)   = String s
    toJSON (U uri) = String $ T.pack $ URI.uriToString id uri ""

instance FromJSON StringOrURI where
    parseJSON (String s) | URI.isURI $ T.unpack s = return $ U $ fromMaybe URI.nullURI $ URI.parseURI $ T.unpack s
    parseJSON (String s)                          = return $ S s
    parseJSON _                                   = mzero

-- $docDecoding
-- There are three use cases supported by the set of decoding/verification
-- functions:
--
-- (1) Unsecured JWTs (<http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-6>).
--      This is supported by the decode function 'decode'.
--      As a client you don't care about signing or encrypting so you only get back a 'JWT' 'UnverifiedJWT'.
--      I.e. the type makes it clear that no signature verification was attempted.
--
-- (2) Signed JWTs you want to verify using a known secret.
--      This is what 'decodeAndVerifySignature' supports, given a secret
--      and JSON it will return a 'JWT' 'VerifiedJWT' if the signature can be
--      verified.
--
-- (3) Signed JWTs that need to be verified using a secret that depends on
--      information contained in the JWT. E.g. the secret depends on
--      some claim, therefore the JWT needs to be decoded first and after
--      retrieving the appropriate secret value, verified in a subsequent step.
--      This is supported by using the `verify` function which given
--      a 'JWT' 'UnverifiedJWT' and a secret will return a 'JWT' 'VerifiedJWT' iff the
--      signature can be verified.
