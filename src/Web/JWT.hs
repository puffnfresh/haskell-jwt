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

This implementation of JWT is based on <http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html> (Version 16)
but currently only implements the minimum required to work with the Atlassian Connect framework.

Known limitations:

   * Only HMAC SHA-256 algorithm is currently a supported signature algorithm

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
    , secret
    -- ** JWT structure
    , claims
    , header
    , signature
    -- ** JWT claims set
    , intDate
    , stringOrURI
    , secondsSinceEpoch
    -- ** JWT header
    , typ
    , cty
    , alg

    -- * Types
    , UnverifiedJWT
    , VerifiedJWT
    , Signature
    , Secret
    , JWT
    , JSON
    , Algorithm(..)
    , JWTClaimsSet(..)
    , IntDate
    , StringOrURI
    , JWTHeader

    , module Data.Default
    ) where

import qualified Data.ByteString.Lazy.Char8 as BL (fromStrict, toStrict)
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE

import           Control.Applicative
import           Control.Monad
import qualified Crypto.Hash.SHA256         as SHA
import qualified Crypto.MAC.HMAC            as HMAC
import           Data.Aeson                 hiding (decode, encode)
import qualified Data.Aeson                 as JSON
import           Data.Default
import qualified Data.HashMap.Strict        as StrictMap
import qualified Data.Map                   as Map
import           Data.Maybe
import           Data.Scientific
import           Data.Time.Clock            (NominalDiffTime)
import qualified Network.URI                as URI
import           Web.Base64
import           Prelude                    hiding (exp)


type JSON = T.Text

-- | The secret used for calculating the message signature
newtype Secret = Secret T.Text deriving (Eq, Show)

newtype Signature = Signature T.Text deriving (Eq, Show)

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
header :: JWT r -> JWTHeader
header (Unverified h _ _ _) = h
header (Verified h _ _) = h

-- | Extract the signature from a verified JSON Web Token
signature :: JWT r -> Maybe Signature
signature Unverified{}     = Nothing
signature (Verified _ _ s) = Just s

-- | A JSON numeric value representing the number of seconds from
-- 1970-01-01T0:0:0Z UTC until the specified UTC date/time.
newtype IntDate = IntDate Integer deriving (Show, Eq, Ord)

-- | Return the seconds since 1970-01-01T0:0:0Z UTC for the given 'IntDate'
secondsSinceEpoch :: IntDate -> NominalDiffTime
secondsSinceEpoch (IntDate s) = fromInteger s

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
                 deriving (Eq, Show)

-- | JWT Header, describes the cryptographic operations applied to the JWT
data JWTHeader = JWTHeader {
    -- | The typ (type) Header Parameter defined by [JWS] and [JWE] is used to
    -- declare the MIME Media Type [IANA.MediaTypes] of this complete JWT in
    -- contexts where this is useful to the application.
    -- This parameter has no effect upon the JWT processing.
    typ :: Maybe T.Text
    -- | The cty (content type) Header Parameter defined by [JWS] and [JWE] is
    -- used by this specification to convey structural information about the JWT.
  , cty :: Maybe T.Text
    -- | The alg (algorithm) used for signing the JWT. The HS256 (HMAC using SHA-256)
    -- is the only required algorithm and the only one supported in this implementation
    -- in addition to "none" which means that no signature will be used.
    --
    -- See <http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#page-6>
  , alg :: Maybe Algorithm
} deriving (Eq, Show)

instance Default JWTHeader where
    def = JWTHeader Nothing Nothing Nothing

-- | The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
data JWTClaimsSet = JWTClaimsSet {
    -- Registered Claim Names
    -- http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#ClaimsContents

    -- | The iss (issuer) claim identifies the principal that issued the JWT.
    iss                :: Maybe StringOrURI

    -- | The sub (subject) claim identifies the principal that is the subject of the JWT.
  , sub                :: Maybe StringOrURI

    -- | The aud (audience) claim identifies the audiences that the JWT is intended for
  , aud                :: Maybe StringOrURI

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


instance Default JWTClaimsSet where
    def = JWTClaimsSet Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty




-- | Encode a claims set using the given secret
--
-- >>> :{
--  let
--      cs = def { -- def returns a default JWTClaimsSet
--         iss = stringOrURI "Foo"
--       , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
--      }
--      key = secret "secret-key"
--  in encodeSigned HS256 key cs
-- :}
-- "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0.vHQHuG3ujbnBUmEp-fSUtYxk27rLiP2hrNhxpyWhb2E"
encodeSigned :: Algorithm -> Secret -> JWTClaimsSet -> JSON
encodeSigned algo secret claims = dotted [header, claim, signature]
    where claim     = encodeJWT claims
          header    = encodeJWT def {
                        typ = Just "JWT"
                      , alg = Just algo
                      }
          signature = calculateDigest algo secret (dotted [header, claim])

-- | Encode a claims set without signing it
--
-- >>> :{
--  let
--      cs = def { -- def returns a default JWTClaimsSet
--      iss = stringOrURI "Foo"
--    , iat = intDate 1394700934
--    , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
--  }
--  in encodeUnsigned cs
-- :}
-- "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjEzOTQ3MDA5MzQsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJGb28ifQ."
encodeUnsigned :: JWTClaimsSet -> JSON
encodeUnsigned claims = dotted [header, claim, ""]
    where claim     = encodeJWT claims
          header    = encodeJWT def {
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
-- Just (JWTHeader {typ = Just "JWT", cty = Nothing, alg = Just HS256})
--
-- and
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mJwt = decode input
--  in fmap claims mJwt
-- :}
-- Just (JWTClaimsSet {iss = Nothing, sub = Nothing, aud = Nothing, exp = Nothing, nbf = Nothing, iat = Nothing, jti = Nothing, unregisteredClaims = fromList [("some",String "payload")]})
decode :: JSON -> Maybe (JWT UnverifiedJWT)
decode input = do
    (h,c,s) <- extractElems $ T.splitOn "." input
    let header' = parseJWT h
        claims' = parseJWT c
    Unverified <$> header' <*> claims' <*> (pure . Signature $ s) <*> (pure . dotted $ [h,c])
    where
        extractElems (h:c:s:_) = Just (h,c,s)
        extractElems _       = Nothing

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
--      mVerifiedJwt = verify (secret "secret") =<< mUnverifiedJwt
--  in signature =<< mVerifiedJwt
-- :}
-- Just (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U")
verify :: Secret -> JWT UnverifiedJWT -> Maybe (JWT VerifiedJWT)
verify secret' (Unverified header' claims' unverifiedSignature originalClaim) = do
   algo <- alg header'
   let calculatedSignature = Signature $ calculateDigest algo secret' originalClaim
   guard (unverifiedSignature == calculatedSignature)
   pure $ Verified header' claims' calculatedSignature

-- | Decode a claims set and verify that the signature matches by using the supplied secret.
-- The algorithm is based on the supplied header value.
--
-- This will return a VerifiedJWT if and only if the signature can be verified
-- using the given secret.
--
-- >>> :{
--  let
--      input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
--      mJwt = decodeAndVerifySignature (secret "secret") input
--  in signature =<< mJwt
-- :}
-- Just (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U")
decodeAndVerifySignature :: Secret -> JSON -> Maybe (JWT VerifiedJWT)
decodeAndVerifySignature secret' input = verify secret' =<< decode input

-- | Try to extract the value for the issue claim field 'iss' from the web token in JSON form
tokenIssuer :: JSON -> Maybe StringOrURI
tokenIssuer = decode >=> fmap pure claims >=> iss

-- | Create a Secret using the given key
-- This will currently simply wrap the given key appropriately buy may
-- return a Nothing in the future if the key needs to adhere to a specific
-- format and the given key is invalid.
secret :: T.Text -> Secret
secret = Secret

-- | Convert the `NominalDiffTime` into an IntDate. Returns a Nothing if the
-- argument is invalid (e.g. the NominalDiffTime must be convertible into a
-- positive Integer representing the seconds since epoch).
intDate :: NominalDiffTime -> Maybe IntDate
intDate i | i < 0 = Nothing
intDate i = Just $ IntDate $ round i

-- | Convert a `T.Text` into a 'StringOrURI`. Returns a Nothing if the
-- String cannot be converted (e.g. if the String contains a ':' but is
-- *not* a valid URI).
stringOrURI :: T.Text -> Maybe  StringOrURI
stringOrURI t | URI.isURI $ T.unpack t = U <$> URI.parseURI (T.unpack t)
stringOrURI t = Just (S t)

-- =================================================================================

encodeJWT :: ToJSON a => a -> T.Text
encodeJWT = base64Encode . TE.decodeUtf8 . BL.toStrict . JSON.encode

parseJWT :: FromJSON a => T.Text -> Maybe a
parseJWT = JSON.decode . BL.fromStrict . TE.encodeUtf8 . base64Decode

dotted :: [T.Text] -> T.Text
dotted = T.intercalate "."


-- =================================================================================

calculateDigest :: Algorithm -> Secret -> T.Text -> T.Text
calculateDigest _ (Secret key) msg = base64Encode' $ HMAC.hmac SHA.hash 64 (bs key) (bs msg)
    where bs = TE.encodeUtf8

-- =================================================================================

type ClaimsMap = Map.Map T.Text Value

fromHashMap :: Object -> ClaimsMap
fromHashMap = Map.fromList . StrictMap.toList

removeRegisteredClaims :: ClaimsMap -> ClaimsMap
removeRegisteredClaims input = Map.differenceWithKey (\_ _ _ -> Nothing) input registeredClaims
    where registeredClaims = Map.fromList $ map (\e -> (e, Null)) ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

instance ToJSON JWTClaimsSet where
    toJSON JWTClaimsSet{..} = object $ catMaybes [
                  fmap ("iss" .=) iss
                , fmap ("sub" .=) sub
                , fmap ("aud" .=) aud
                , fmap ("exp" .=) exp
                , fmap ("nbf" .=) nbf
                , fmap ("iat" .=) iat
                , fmap ("jti" .=) jti
            ] ++ Map.toList (removeRegisteredClaims unregisteredClaims)


instance FromJSON JWTClaimsSet where
        parseJSON = withObject "JWTClaimsSet"
                     (\o -> JWTClaimsSet
                     <$> o .:? "iss"
                     <*> o .:? "sub"
                     <*> o .:? "aud"
                     <*> o .:? "exp"
                     <*> o .:? "nbf"
                     <*> o .:? "iat"
                     <*> o .:? "jti"
                     <*> pure (removeRegisteredClaims $ fromHashMap o))



instance FromJSON JWTHeader where
    parseJSON = withObject "JWTHeader"
                    (\o -> JWTHeader
                    <$> o .:? "typ"
                    <*> o .:? "cty"
                    <*> o .:? "alg")

instance ToJSON JWTHeader where
    toJSON JWTHeader{..} = object $ catMaybes [
                  fmap ("typ" .=) typ
                , fmap ("cty" .=) cty
                , fmap ("alg" .=) alg
            ]

instance ToJSON IntDate where
    toJSON (IntDate i) = Number $ scientific (fromIntegral i) 0

instance FromJSON IntDate where
    parseJSON (Number x) = return $ IntDate $ coefficient x
    parseJSON _          = mzero

instance ToJSON Algorithm where
    toJSON HS256 = String ("HS256"::T.Text)

instance FromJSON Algorithm where
    parseJSON (String "HS256") = return HS256
    parseJSON _                = mzero

instance ToJSON StringOrURI where
    toJSON (S s) = String s
    toJSON (U uri) = String $ T.pack $ URI.uriToString id uri ""

instance FromJSON StringOrURI where
    parseJSON (String s) | URI.isURI $ T.unpack s = return $ U $ fromMaybe URI.nullURI $ URI.parseURI $ T.unpack s
    parseJSON (String s) = return $ S s
    parseJSON _          = mzero

-- $docDecoding
-- There are three use cases supported by the set of decoding/verification
-- functions:
--
-- (1) Plaintext JWTs (<http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-16#section-6>).
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
