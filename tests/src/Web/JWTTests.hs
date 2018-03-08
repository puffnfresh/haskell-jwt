{-# LANGUAGE BangPatterns, OverloadedStrings, ScopedTypeVariables, TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Web.JWTTests
  (
    main
  , defaultTestGroup
) where

import           Test.Tasty
import           Test.Tasty.TH
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import qualified Test.QuickCheck as QC
import qualified Data.Map              as Map
import qualified Data.Text             as T
import qualified Data.Text.Lazy        as TL
import qualified Data.ByteString as BS
import           Data.Aeson.Types
import           Data.Maybe
import           Data.String (fromString)
import           Data.Time
import           Web.JWT

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

case_stringOrURIString = do
    let str = "foo bar baz 2312j!@&^#^*!(*@"
        sou = stringOrURI str
    Just str @=? fmap (T.pack . show) sou

case_stringOrURI= do
    let str = "http://user@example.com:8900/foo/bar?baz=t;"
        sou = stringOrURI str
    Just str @=? fmap (T.pack . show) sou

case_numericDateDeriveOrd = do
    let i1 = numericDate 1231231231 -- Tue  6 Jan 2009 19:40:31 AEDT
        i2 = numericDate 1231232231 -- Tue  6 Jan 2009 19:57:11 AEDT
    LT @=? i1 `compare` i2

case_decodeJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decode input
    True @=? isJust mJwt
    True @=? isJust (fmap signature mJwt)
    let (Just unverified) = mJwt
    Just HS256 @=? alg (header unverified)
    Just "payload" @=? Map.lookup "some" (unClaimsMap $ unregisteredClaims $ claims unverified)

case_verify = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mVerified = verify (hmacSecret "secret") =<< decode input
    True @=? isJust mVerified

case_decodeAndVerifyJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decodeAndVerifySignature (hmacSecret "secret") input
    True @=? isJust mJwt
    let (Just verified) = mJwt
    Just HS256 @=? alg (header verified)
    Just "payload" @=? Map.lookup "some" (unClaimsMap $ unregisteredClaims $ claims verified)

-- It must be impossible to get a VerifiedJWT if alg is "none"
case_decodeAndVerifyJWTAlgoNone = do
    {-
    - Header:
            {
              "alg": "none",
              "typ": "JWT"
            }
      Payload:
            {
              "iss": "https://jwt-idp.example.com",
              "sub": "mailto:mike@example.com",
              "nbf": 1425980755,
              "exp": 1425984355,
              "iat": 1425980755,
              "jti": "id123456",
              "typ": "https://example.com/register"
            }
    -}
    let input = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTQyNTk4MDc1NSwiZXhwIjoxNDI1OTg0MzU1LCJpYXQiOjE0MjU5ODA3NTUsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9."
        mJwt = decodeAndVerifySignature (hmacSecret "secretkey") input
    False @=? isJust mJwt

case_decodeAndVerifyJWTFailing = do
    -- Generated with ruby-jwt, modified to be invalid
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2u"
        mJwt = decodeAndVerifySignature (hmacSecret "secret") input
    False @=? isJust mJwt

case_decodeInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map decode inputs
    True @=? all isNothing result

case_decodeAndVerifySignatureInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map (decodeAndVerifySignature (hmacSecret "secret")) inputs
    True @=? all isNothing result

case_encodeJWTNoMac = do
    let cs = mempty {
        iss = stringOrURI "Foo"
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
        jwt = encodeUnsigned cs mempty
    -- Verify the shape of the JWT, ensure the shape of the triple of
    -- <header>.<claims>.<signature>
    let (h:c:s:_) = T.splitOn "." jwt
    False @=? T.null h
    False @=? T.null c
    True  @=? T.null s


case_encodeDecodeJWTNoMac = do
    let cs = mempty {
        iss = stringOrURI "Foo"
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
        mJwt = decode $ encodeUnsigned cs mempty
    True @=? isJust mJwt
    let (Just unverified) = mJwt
    cs @=? claims unverified

case_encodeDecodeJWT = do
    let now = 1394573404
        cs = mempty {
        iss = stringOrURI "Foo"
      , iat = numericDate now
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
        key = hmacSecret "secret-key"
        mJwt = decode $ encodeSigned key mempty cs
    let (Just claims') = fmap claims mJwt
    cs @=? claims'
    Just now @=? fmap secondsSinceEpoch (iat claims')

case_tokenIssuer = do
    let iss' = stringOrURI "Foo"
        cs = mempty {
        iss = iss'
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
        key = hmacSecret "secret-key"
        t   = encodeSigned key mempty cs
    iss' @=? tokenIssuer t

case_encodeDecodeJWTClaimsSetCustomClaims = do
    let now = 1234
        cs = mempty {
        iss = stringOrURI "Foo"
      , iat = numericDate now
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
    let secret' = hmacSecret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned secret' mempty cs
    Just cs @=? fmap claims jwt

case_encodeDecodeJWTClaimsSetWithSingleAud = do
    let now = 1234
        cs = mempty {
            iss = stringOrURI "Foo"
          , aud = Left <$> stringOrURI "single-audience"
          , iat = numericDate now
        }
    let secret' = hmacSecret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned secret' mempty cs
    Just cs @=? fmap claims jwt

case_encodeDecodeJWTClaimsSetWithMultipleAud = do
    let now = 1234
        cs = mempty {
            iss = stringOrURI "Foo"
          , aud = Right <$> (:[]) <$> stringOrURI "audience"
          , iat = numericDate now
        }
    let secret' = hmacSecret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned secret' mempty cs
    Just cs @=? fmap claims jwt

case_encodeDecodeJWTClaimsSetBinarySecret = do
    let now = 1234
        cs = mempty {
            iss = stringOrURI "Foo"
          , iat = numericDate now
        }
    secretKey <- BS.readFile "tests/jwt.secret.1"
    let secret' = HMACSecret secretKey
        jwt = decodeAndVerifySignature secret' $ encodeSigned secret' mempty cs
    Just cs @=? fmap claims jwt

prop_stringOrURIProp = f
    where f :: StringOrURI -> Bool
          f sou = let s = stringOrURI $ T.pack $ show sou
                  in Just sou == s

prop_stringOrURIToText= f
    where f :: T.Text -> Bool
          f t = let mSou = stringOrURI t
                in case mSou of
                       Just sou -> stringOrURIToText sou == t
                       Nothing  -> True

prop_encode_decode = f
    where f :: T.Text -> JWTClaimsSet -> Bool
          f key claims' = let Just unverified = (decode $ encodeSigned (hmacSecret key) mempty claims')
                          in claims unverified == claims'

prop_encode_decode_binary_secret = f
    where f :: BS.ByteString -> JWTClaimsSet -> Bool
          f binary claims' = let Just unverified = (decode $ encodeSigned (HMACSecret binary) mempty claims')
                          in claims unverified == claims'

prop_encode_decode_verify_signature = f
    where f :: T.Text -> JWTClaimsSet -> Bool
          f key' claims' = let key = hmacSecret key'
                               Just verified = (decodeAndVerifySignature key $ encodeSigned key mempty claims')
                           in claims verified == claims'


instance Arbitrary JWTClaimsSet where
    arbitrary = JWTClaimsSet <$> arbitrary
                             <*> arbitrary
                             <*> arbitrary
                             <*> arbitrary
                             <*> arbitrary
                             <*> arbitrary
                             <*> arbitrary
                             <*> arbitrary

instance Arbitrary ClaimsMap where
    arbitrary = return $ ClaimsMap Map.empty

instance Arbitrary NumericDate where
    arbitrary = fmap (f . numericDate) (arbitrary :: QC.Gen NominalDiffTime)
        where f = fromMaybe (fromJust $ numericDate 1)

instance Arbitrary NominalDiffTime where
    arbitrary = arbitrarySizedFractional
    shrink    = shrinkRealFrac

instance Arbitrary StringOrURI where
    arbitrary = fmap (f . stringOrURI) (arbitrary :: QC.Gen T.Text)
        where
            f = fromMaybe (fromJust $ stringOrURI "http://example.com")

instance Arbitrary BS.ByteString where
    arbitrary = BS.pack <$> arbitrary
    shrink xs = BS.pack <$> shrink (BS.unpack xs)

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
