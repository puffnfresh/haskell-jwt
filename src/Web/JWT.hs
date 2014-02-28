{-# LANGUAGE RecordWildCards, OverloadedStrings #-}
{-# LANGUAGE CPP #-}

-- TODO:
--   * there is currently no verification of time related information
--   * Only HMAC SHA256 is supported
--   * Registered claims are not validated
--   * StringOrUri is not valdiated

-- | JSON Web Token used for Atlassian Connect
-- This is based on http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html (Version 16)
-- but currently only implements the minimum required to work with the Atlassian Connect framework.
module Web.JWT (
    decode
  , decodeAndVerify
  , encode
  , tokenIssuer
  , secret
  , Signature(..)
  , JWT(..)
  , Algorithm(..)
  , JWTClaimsSet(..)
  , module Data.Default
#ifdef TEST
  , IntDate(..)
  , JWTHeader(..)
  , base64Encode
  , base64Decode
#endif
) where

import qualified Data.Text.Lazy             as T
import qualified Data.Text                  as TS
import qualified Data.Text.Lazy.Encoding    as TE
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Data.ByteString.Char8      as BS

import qualified Data.Aeson                 as JSON
import qualified Data.Map                   as Map
import qualified Data.HashMap.Strict        as StrictMap
import qualified Data.ByteString.Base64.URL as BASE64
import qualified Crypto.Hash.SHA256         as SHA
import qualified Crypto.MAC.HMAC            as HMAC
import           Control.Applicative
import           Control.Monad
import           Data.Maybe
import           Prelude hiding             (exp)
import           Data.Aeson hiding          (decode, encode)
import           Data.Scientific
import           Data.Default

newtype Secret = Secret T.Text deriving (Eq, Show)
newtype Signature = Signature T.Text deriving (Eq, Show)

data JWT = UnverifiedJWT { header :: JWTHeader, claims :: JWTClaimsSet } |
            VerifiedJWT JWTHeader JWTClaimsSet Signature deriving (Eq, Show)

-- | A JSON numeric value representing the number of seconds from
--   1970-01-01T0:0:0Z UTC until the specified UTC date/time.
newtype IntDate = IntDate Integer deriving (Eq, Show)

data Algorithm = HS256 -- HMAC SHA-256
               | NONE
                deriving (Eq, Show)

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

    -- The iss (issuer) claim identifies the principal that issued the JWT.
    iss :: Maybe T.Text

    -- The sub (subject) claim identifies the principal that is the subject of the JWT.
  , sub :: Maybe T.Text

    -- The aud (audience) claim identifies the audiences that the JWT is intended for
  , aud :: Maybe T.Text

    -- The exp (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Its value MUST be a number containing an IntDate value.
  , exp :: Maybe IntDate

    -- The nbf (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
  , nbf :: Maybe IntDate

    -- The iat (issued at) claim identifies the time at which the JWT was issued.
  , iat :: Maybe IntDate

    -- The jti (JWT ID) claim provides a unique identifier for the JWT.
  , jti :: Maybe T.Text

  , unregisteredClaims :: ClaimsMap

} deriving (Eq, Show)


instance Default JWTClaimsSet where
    def = JWTClaimsSet Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty


-- | Encode a claims set using the given secret
encode :: Secret -> JWTClaimsSet -> T.Text
encode secret' claims = dotted [header, claim, signature]
    where claim     = encodeJWT claims
          header    = encodeJWT  def {
                        typ = Just "JWT"
                      , alg = Just HS256
                      }
          signature = calculateDigest HS256 secret' (dotted [header, claim])
          encodeJWT :: ToJSON a => a -> T.Text
          encodeJWT = base64Encode . TE.decodeUtf8 . JSON.encode

-- | Decode a claims set without verifying the signature
decode :: T.Text -> Maybe JWT
decode input = let (h:c:_) = T.splitOn "." input
                   header  = parseJWT h
                   claims  = parseJWT c
               in UnverifiedJWT <$> header <*> claims

tokenIssuer :: T.Text -> Maybe T.Text
tokenIssuer = decode >=> fmap pure claims >=> iss

-- | Decode a claims set and verify that the signature matches by using the supplied secret
decodeAndVerify :: Secret -> T.Text -> Maybe JWT
decodeAndVerify secret' input = do
        let (h:c:s:_) = T.splitOn "." input
        header <- parseJWT h
        claims <- parseJWT c
        let sign = if s == calculateMessageDigest h c then pure $ Signature s else mzero
        VerifiedJWT <$> header <*> claims <*> sign
      where calculateMessageDigest header claims = calculateDigest HS256 secret' (dotted [header, claims])

parseJWT :: FromJSON a => T.Text -> Maybe a
parseJWT = JSON.decode . TE.encodeUtf8 . base64Decode

dotted :: [T.Text] -> T.Text
dotted = T.intercalate "."

-- | Create a Secret using the given key
secret :: T.Text -> Secret
secret = Secret

-- =================================================================================

base64Decode :: T.Text -> T.Text
base64Decode = operateOnText BASE64.decodeLenient

base64Encode :: T.Text -> T.Text
base64Encode = removePaddingBase64Encoding . operateOnText BASE64.encode

operateOnText :: (BS.ByteString -> BS.ByteString) -> T.Text -> T.Text
operateOnText f = TE.decodeUtf8 . strictToLazy . f . lazyToStrictBS . TE.encodeUtf8
    where strictToLazy = B.fromStrict
          lazyToStrictBS = BS.concat . B.toChunks

removePaddingBase64Encoding :: T.Text -> T.Text
removePaddingBase64Encoding = T.dropWhileEnd (=='=')

calculateDigest :: Algorithm -> Secret -> T.Text -> T.Text
calculateDigest _ (Secret key) msg = base64Encode' $ HMAC.hmac SHA.hash 64 (toStrict key) (toStrict msg)
    where toStrict = BS.concat . B.toChunks . TE.encodeUtf8
          base64Encode' = removePaddingBase64Encoding . TE.decodeUtf8 . B.fromStrict . BASE64.encode

-- =================================================================================

type ClaimsMap = Map.Map TS.Text Value

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
    toJSON HS256 = String ("HS256"::TS.Text)
    toJSON NONE  = String ("NONE"::TS.Text)

instance FromJSON Algorithm where
    parseJSON (String "HS256") = return HS256
    parseJSON (String "NONE")  = return NONE
    parseJSON _                = mzero
