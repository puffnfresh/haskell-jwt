{-# Language DeriveFunctor #-}
{-# language DeriveGeneric #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# language OverloadedStrings #-}
module Web.JWT.Validate (decodeJWT, decodeValidateJWT, AuthException(..), JWTClaims, jcAud, jcExp, jcIat, jcNbf, jcSub, jcEmail, UserSub, userSub, UserEmail, userEmail, ApiAudience, apiAudience) where

import Control.Monad.IO.Class (MonadIO(..))
import qualified Data.List.NonEmpty as NE (NonEmpty(..))
import Data.Maybe (fromMaybe)
import GHC.Exception (Exception(..))
import GHC.Generics (Generic)
import Data.String (IsString(..))
import Data.Typeable

-- aeson
import qualified Data.Aeson as A (FromJSON(..), ToJSON(..), ToJSONKey(..), FromJSON(..), FromJSONKey(..), Value(..))
-- containers
import qualified Data.Map.Strict as M (Map, lookup)
-- -- hoauth2
-- import Network.OAuth.OAuth2 (OAuth2Token(..), IdToken(..))
-- jwt
import qualified Web.JWT as J (decode, claims, JWTClaimsSet(..), StringOrURI, NumericDate, ClaimsMap(..))
-- scientific
import Data.Scientific (coefficient)
-- text
import qualified Data.Text as T (Text, unpack)
-- time
import Data.Time (UTCTime(..), NominalDiffTime, getCurrentTime, fromGregorian, addUTCTime, diffUTCTime)
-- validation-selective
import Validation (Validation(..), failure, validationToEither, maybeToSuccess)


-- | 'sub' field
newtype UserSub = UserSub { userSub :: T.Text }
  deriving (Eq, Ord, Generic, IsString)
  deriving newtype (Show, A.ToJSON, A.FromJSON, A.ToJSONKey, A.FromJSONKey)

newtype UserEmail = UserEmail { userEmail :: T.Text }
  deriving (Eq, Ord, Generic, IsString)
  deriving newtype (Show, A.ToJSON, A.FromJSON, A.ToJSONKey, A.FromJSONKey)

-- | intended audience of the token (== API key ID )
newtype ApiAudience = ApiAudience { apiAudience :: T.Text} deriving (Eq, Ord, Show, Generic, Typeable, IsString)
instance A.ToJSON ApiAudience

-- | Decoded claims from the JWT token, valid (at least) for the Google OpenID implementation as of February 2021
--
data JWTClaims =
  JWTClaims {
    jcAud :: T.Text -- ^ "aud"ience field
  , jcExp :: UTCTime -- ^ "exp"iry date
  , jcIat :: UTCTime -- ^ Issued AT
  , jcNbf :: UTCTime -- ^ Not BeFore
  , jcSub :: UserSub -- ^ "sub"ject
  , jcEmail :: UserEmail
            } deriving (Eq, Show)

-- | Decode and validate the 'aud', 'exp' and 'nbf' fields of the JWT
decodeValidateJWT :: MonadIO f =>
                     ApiAudience -- ^ intended token audience (its meaning depends on the OAuth identity provider )
                  -> Maybe NominalDiffTime -- ^ buffer period to allow for API roundtrip delays (defaults to 0 if Nothing)
                  -> T.Text -- ^ JWT-encoded string, e.g. the contents of the id_token field
                  -> f (Either (NE.NonEmpty AuthException) JWTClaims)
decodeValidateJWT iaud nsecs jstr = case validationToEither $ decodeJWT jstr of
  Right jwc -> validationToEither <$> validateJWT iaud nsecs jwc
  Left e -> pure $ Left e


-- | Validate the 'aud', 'exp' and 'nbf' fields
validateJWT :: MonadIO m =>
               ApiAudience -- ^ intended token audience (its meaning depends on the OAuth identity provider )
            -> Maybe NominalDiffTime
            -> JWTClaims
            -> m (Validation (NE.NonEmpty AuthException) JWTClaims)
validateJWT a nsecs j = do
  t <- liftIO getCurrentTime
  pure (
    JWTClaims <$>
      validateAud a (jcAud j) <*>
      validateExp nsecs t (jcExp j) <*>
      pure (jcIat j) <*>
      validateNbf t (jcNbf j) <*>
      pure (jcSub j) <*>
      pure (jcEmail j)
       )

-- | Fails if the 'exp'iry field is not at least 'nsecs' seconds in the future
validateExp :: Maybe NominalDiffTime -- ^ defaults to 0 if Nothing
            -> UTCTime -> UTCTime -> Validation (NE.NonEmpty AuthException) UTCTime
validateExp nsecs t texp = do
  if fromMaybe 0 nsecs `addUTCTime` texp > t then
    Success texp
    else failure (AEExpiredToken texp)

-- | Fails if the current time is before the 'nbf' time (= token is not yet valid)
validateNbf :: UTCTime -> UTCTime -> Validation (NE.NonEmpty AuthException) UTCTime
validateNbf t tnbf = do
  if t `diffUTCTime` tnbf > 0 then
    Success tnbf
    else failure (AENotYetValid tnbf)


-- | Fails if the 'aud'ience field is not equal to the supplied ApiAudience
validateAud :: ApiAudience -- ^ intended audience of the token (== API key ID )
            -> T.Text
            -> Validation (NE.NonEmpty AuthException) T.Text
validateAud aa@(ApiAudience a) audt
  | a == audt = Success audt
  | otherwise = failure $ AEAudienceNotFound aa

-- | Ensure all fields are present
decodeJWT :: T.Text
          -> Validation (NE.NonEmpty AuthException) JWTClaims
decodeJWT jwts = case J.claims <$> J.decode jwts of
  Nothing -> failure $ AEMalformedJWT jwts
  Just (J.JWTClaimsSet _ subm audm expm nbfm iatm _ (J.ClaimsMap cms)) ->
    JWTClaims <$>
      decAud audm <*>
      decExp expm <*>
      decIat iatm <*>
      decNbf nbfm <*>
      decSub subm <*>
      decEmail cms

decAud :: Maybe (Either J.StringOrURI [J.StringOrURI])
       -> Validation (NE.NonEmpty AuthException) T.Text
decAud aam = claimNotFound "aud" (fromAud aam)

decExp :: Maybe J.NumericDate -> Validation (NE.NonEmpty AuthException) UTCTime
decExp em = claimNotFound "exp" (fromNumericDate em)

decIat :: Maybe J.NumericDate -> Validation (NE.NonEmpty AuthException) UTCTime
decIat im = claimNotFound "iat" (fromNumericDate im)

decNbf :: Maybe J.NumericDate
       -> Validation (NE.NonEmpty AuthException) UTCTime
decNbf im = claimNotFound "nbf" (fromNumericDate im)

decSub :: A.ToJSON a =>
          Maybe a -> Validation (NE.NonEmpty AuthException) UserSub
decSub sm = claimNotFound "sub" (UserSub <$> fromStringOrUri sm)

decEmail :: (Ord k, IsString k) =>
            M.Map k A.Value -> Validation (NE.NonEmpty AuthException) UserEmail
decEmail cms = claimNotFound "email" (case M.lookup "email" cms of
                                           Just (A.String ems) -> Just $ UserEmail ems
                                           _ -> Nothing)

claimNotFound :: String -> Maybe a -> Validation (NE.NonEmpty AuthException) a
claimNotFound c = maybeToSuccess (AEClaimNotFound c NE.:| [])

-- | Possible exception states of authentication request
data AuthException = AEMalformedJWT T.Text
                   | AEClaimNotFound String
                   | AEAudienceNotFound ApiAudience
                   | AEExpiredToken UTCTime
                   | AENotYetValid UTCTime
                   | AENoToken
                   deriving (Eq, Ord, Generic, Typeable)

instance Show AuthException where
  show = \case
    AEMalformedJWT jt -> unwords ["Cannot decode JWT token :", T.unpack jt]
    AEClaimNotFound c -> unwords ["JWT claim not found :", c]
    AEAudienceNotFound a -> unwords ["audience", show a, "not found"]
    AEExpiredToken t -> unwords ["JWT token expired on", show t]
    AENotYetValid t -> unwords ["JWT token not yet valid:", show t]
    AENoToken -> "No token found"
instance Exception AuthException
instance A.ToJSON AuthException

fromAud :: Maybe (Either J.StringOrURI [J.StringOrURI]) -> Maybe T.Text
fromAud mm = maybe Nothing f mm
  where
    g str = case A.toJSON str of
      A.String s -> Just s
      _ -> Nothing
    f = \case
      Left sou -> g sou
      Right sous -> mconcat <$> traverse g sous

fromNumericDate :: Maybe J.NumericDate -> Maybe UTCTime
fromNumericDate tjm = case A.toJSON tjm of
  A.Number x -> Just $ addUTCTime (fromIntegral $ coefficient x) epoch
  _ -> Nothing

fromStringOrUri :: (A.ToJSON a) => Maybe a -> Maybe T.Text
fromStringOrUri sm = case A.toJSON sm of
  A.String t -> Just t
  _ -> Nothing

epoch :: UTCTime
epoch = UTCTime (fromGregorian 1970 1 1) 0

