{-# LANGUAGE CPP               #-}
{-# LANGUAGE EmptyDataDecls    #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE StandaloneDeriving   #-}

-- TODO:
--   * StringOrUri is not valdiated

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
      decode
    , decodeAndVerifySignature
    , encodeSigned
    , encodeUnsigned

    -- * Utility functions
    , tokenIssuer
    , secret
    , claims
    , header
    , signature
    , module Data.Default

    -- * Types
    , UnverifiedJWT
    , VerifiedJWT
    , Signature
    , Secret
    , JWT
    , JSON
    , Algorithm(..)
    , JWTClaimsSet(..)

#ifdef TEST
    , IntDate(..)
    , JWTHeader(..)
    , base64Encode
    , base64Decode
#endif
    ) where

import qualified Data.ByteString.Char8      as B
import qualified Data.ByteString.Lazy.Char8 as BL (fromStrict, toStrict)
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE

import           Control.Applicative
import           Control.Monad
import qualified Crypto.Hash.SHA256         as SHA
import qualified Crypto.MAC.HMAC            as HMAC
import           Data.Aeson                 hiding (decode, encode)
import qualified Data.Aeson                 as JSON
import qualified Data.ByteString.Base64.URL as BASE64
import           Data.Default
import qualified Data.HashMap.Strict        as StrictMap
import qualified Data.Map                   as Map
import           Data.Maybe
import           Data.Scientific
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
   Unverified :: JWTHeader -> JWTClaimsSet -> JWT UnverifiedJWT
   Verified   :: JWTHeader -> JWTClaimsSet -> Signature -> JWT VerifiedJWT

deriving instance Show (JWT r)

-- | Extract the claims set from a JSON Web Token
claims :: JWT r -> JWTClaimsSet
claims (Unverified _ c) = c
claims (Verified _ c _) = c

-- | Extract the header from a JSON Web Token
header :: JWT r -> JWTHeader
header (Unverified h _) = h
header (Verified h _ _) = h

-- | Extract the signature from a verified JSON Web Token
signature :: JWT r -> Maybe Signature
signature (Unverified _ _) = Nothing
signature (Verified _ _ s) = Just s

-- | A JSON numeric value representing the number of seconds from
--   1970-01-01T0:0:0Z UTC until the specified UTC date/time.
newtype IntDate = IntDate Integer deriving (Eq, Show)

data Algorithm = HS256 -- ^ HMAC using SHA-256 hash algorithm
                 deriving (Eq, Show)

-- | JWT Header, describes the cryptographic operations applied to the JWT
data JWTHeader = JWTHeader {
    typ :: Maybe T.Text
  , cty :: Maybe T.Text
  , alg :: Maybe Algorithm
} deriving (Eq, Show)

instance Default JWTHeader where
    def = JWTHeader Nothing Nothing Nothing

-- | The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
data JWTClaimsSet = JWTClaimsSet {
    -- Registered Claim Names
    -- http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#ClaimsContents

    -- | The iss (issuer) claim identifies the principal that issued the JWT.
    iss                :: Maybe T.Text

    -- | The sub (subject) claim identifies the principal that is the subject of the JWT.
  , sub                :: Maybe T.Text

    -- | The aud (audience) claim identifies the audiences that the JWT is intended for
  , aud                :: Maybe T.Text

    -- | The exp (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Its value MUST be a number containing an IntDate value.
  , exp                :: Maybe IntDate

    -- | The nbf (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
  , nbf                :: Maybe IntDate

    -- | The iat (issued at) claim identifies the time at which the JWT was issued.
  , iat                :: Maybe IntDate

    -- | The jti (JWT ID) claim provides a unique identifier for the JWT.
  , jti                :: Maybe T.Text

  , unregisteredClaims :: ClaimsMap

} deriving (Eq, Show)


instance Default JWTClaimsSet where
    def = JWTClaimsSet Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty


-- | Encode a claims set using the given secret
--
-- > {-# LANGUAGE OverloadedStrings #-}
-- >
-- > let cs = def {  -- def returns a default JWTClaimsSet
-- >     iss = Just "Foo"
-- >   , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
-- > }
-- >     key = secret "secret-key"
-- >     jwt = encodeSigned HS256 key cs
--
-- This yields:
--
-- > >>> jwt
-- > "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0.vHQHuG3ujbnBUmEp-fSUtYxk27rLiP2hrNhxpyWhb2E"
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
-- > {-# LANGUAGE OverloadedStrings #-}
-- >
-- > let cs = def {  -- def returns a default JWTClaimsSet
-- >     iss = Just "Foo"
-- >   , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
-- > }
-- >     jwt = encodeUnsigned cs
--
-- This yields:
--
-- > >>> jwt
-- > "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0."
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
-- > import qualified Data.Text as T
-- > let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
-- >     mJwt = decode input
-- >     mHeader = fmap header mJwt
-- >     mClaims = fmap claims mJwt
-- >     mSignature = join $ fmap signature mJwt
--
-- This yields:
--
-- > >>> mHeader
-- > Just (JWTHeader {typ = Just "JWT", cty = Nothing, alg = Just HS256})
--
-- and
--
-- > >>> mClaims
-- > Just (JWTClaimsSet {iss = Nothing, sub = Nothing, aud = Nothing,
-- >     exp = Nothing, nbf = Nothing, iat = Nothing, jti = Nothing,
-- >     unregisteredClaims = fromList [("some",String "payload")]})
--
-- and
--
-- > >>> mSignature
-- > Nothing
decode :: JSON -> Maybe (JWT UnverifiedJWT)
decode input = do
    (h,c) <- extractElems $ T.splitOn "." input
    let header' = parseJWT h
        claims' = parseJWT c
    Unverified <$> header' <*> claims'
    where
        extractElems (h:c:_) = Just (h,c)
        extractElems _       = Nothing


-- | Decode a claims set and verify that the signature matches by using the supplied secret.
-- The algorithm is based on the supplied header value. 
--
-- This will return a VerifiedJWT if and only if the signature can be verified
-- using the given secret.
--
-- > import qualified Data.Text as T
-- > let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U" :: T.Text
-- >     mJwt = decodeAndVerifySignature (secret "secret") input
-- >     mSignature = join $ fmap signature mJwt
--
-- This yields:
--
-- > >>> mJwt
-- > Just (Verified (JWTHeader {typ = Just "JWT", cty = Nothing, alg = Just HS256})
-- >    (JWTClaimsSet {iss = Nothing, sub = Nothing, aud = Nothing, exp = Nothing,
-- >     nbf = Nothing, iat = Nothing, jti = Nothing,
-- >     unregisteredClaims = fromList [("some",String "payload")]})
-- >    (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"))
--
-- and
--
-- > >>> mSignature
-- > Just (Signature "Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U")
decodeAndVerifySignature :: Secret -> T.Text -> Maybe (JWT VerifiedJWT)
decodeAndVerifySignature secret' input = do
        (h,c,s) <- extractElems $ T.splitOn "." input
        header' <- parseJWT h
        claims' <- parseJWT c
        algo  <- fmap alg header'
        let sign = if Just s == calculateMessageDigest h c algo then pure $ Signature s else mzero
        Verified <$> header' <*> claims' <*> sign
    where
      calculateMessageDigest header' claims' (Just algo') = Just $ calculateDigest algo' secret' (dotted [header', claims'])
      calculateMessageDigest _ _ Nothing = Nothing
      extractElems (h:c:s:_) = Just (h,c,s)
      extractElems _         = Nothing

-- | Try to extract the value for the issue claim field 'iss' from the web token in JSON form
tokenIssuer :: JSON -> Maybe T.Text
tokenIssuer = decode >=> fmap pure claims >=> iss

-- | Create a Secret using the given key
-- This will currently simply wrap the given key appropriately buy may
-- return a Nothing in the future if the key needs to adhere to a specific
-- format and the given key is invalid.
secret :: T.Text -> Secret
secret = Secret

-- =================================================================================

encodeJWT :: ToJSON a => a -> T.Text
encodeJWT = base64Encode . TE.decodeUtf8 . BL.toStrict . JSON.encode

parseJWT :: FromJSON a => T.Text -> Maybe a
parseJWT = JSON.decode . BL.fromStrict . TE.encodeUtf8 . base64Decode

dotted :: [T.Text] -> T.Text
dotted = T.intercalate "."


-- =================================================================================


base64Decode :: T.Text -> T.Text
base64Decode = operateOnText BASE64.decodeLenient

base64Encode :: T.Text -> T.Text
base64Encode = removePaddingBase64Encoding . operateOnText BASE64.encode

operateOnText :: (B.ByteString -> B.ByteString) -> T.Text -> T.Text
operateOnText f = TE.decodeUtf8 . f . TE.encodeUtf8

removePaddingBase64Encoding :: T.Text -> T.Text
removePaddingBase64Encoding = T.dropWhileEnd (=='=')

calculateDigest :: Algorithm -> Secret -> T.Text -> T.Text
calculateDigest _ (Secret key) msg = base64Encode' $ HMAC.hmac SHA.hash 64 (bs key) (bs msg)
    where bs = TE.encodeUtf8
          base64Encode' = removePaddingBase64Encoding . TE.decodeUtf8 . BASE64.encode

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
    toJSON (IntDate ts) = Number $ scientific (fromIntegral ts) 0

instance FromJSON IntDate where
    parseJSON (Number x) = return $ IntDate $ coefficient x
    parseJSON _          = mzero

instance ToJSON Algorithm where
    toJSON HS256 = String ("HS256"::T.Text)

instance FromJSON Algorithm where
    parseJSON (String "HS256") = return HS256
    parseJSON _                = mzero
