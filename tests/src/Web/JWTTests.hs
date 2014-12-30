{-# LANGUAGE BangPatterns, OverloadedStrings, ScopedTypeVariables, TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
module Web.JWTTests
  (
    main
  , defaultTestGroup
) where

import           Control.Applicative
import           Test.Tasty
import           Test.Tasty.TH
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import qualified Test.QuickCheck as QC
import qualified Data.Map              as Map
import qualified Data.Text             as T
import qualified Data.Text.Lazy        as TL
import           Data.Aeson.Types
import           Data.Maybe
import           Data.String (fromString, IsString)
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


case_intDateDeriveOrd = do
    let i1 = intDate 1231231231 -- Tue  6 Jan 2009 19:40:31 AEDT
        i2 = intDate 1231232231 -- Tue  6 Jan 2009 19:57:11 AEDT
    LT @=? i1 `compare` i2


case_decodeJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decode input
    True @=? isJust mJwt
    True @=? isJust (fmap signature mJwt)
    let (Just unverified) = mJwt
    Just HS256 @=? alg (header unverified)
    Just "payload" @=? Map.lookup "some" (unregisteredClaims $ claims unverified)

case_verify = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mVerified = verify (secret "secret") =<< decode input
    True @=? isJust mVerified

case_decodeAndVerifyJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decodeAndVerifySignature (secret "secret") input
    True @=? isJust mJwt
    let (Just verified) = mJwt
    Just HS256 @=? alg (header verified)
    Just "payload" @=? Map.lookup "some" (unregisteredClaims $ claims verified)

case_decodeAndVerifyJWTFailing = do
    -- Generated with ruby-jwt, modified to be invalid
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2u"
        mJwt = decodeAndVerifySignature (secret "secret") input
    False @=? isJust mJwt

case_decodeInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map decode inputs
    True @=? all isNothing result

case_decodeAndVerifySignatureInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map (decodeAndVerifySignature (secret "secret")) inputs
    True @=? all isNothing result

case_encodeJWTNoMac = do
    let cs = def {
        iss = stringOrURI "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", Bool True)]
    }
        jwt = encodeUnsigned cs
    -- Verify the shape of the JWT, ensure the shape of the triple of
    -- <header>.<claims>.<signature>
    let (h:c:s:_) = T.splitOn "." jwt
    False @=? T.null h
    False @=? T.null c
    True  @=? T.null s


case_encodeDecodeJWTNoMac = do
    let cs = def {
        iss = stringOrURI "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", Bool True)]
    }
        mJwt = decode $ encodeUnsigned cs
    True @=? isJust mJwt
    let (Just unverified) = mJwt
    cs @=? claims unverified

case_encodeDecodeJWT = do
    let now = 1394573404
        cs = def {
        iss = stringOrURI "Foo"
      , iat = intDate now
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", Bool True)]
    }
        key = secret "secret-key"
        mJwt = decode $ encodeSigned HS256 key cs
    let (Just claims') = fmap claims mJwt
    cs @=? claims'
    Just now @=? fmap secondsSinceEpoch (iat claims')

case_tokenIssuer = do
    let iss' = stringOrURI "Foo"
        cs = def {
        iss = iss'
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", Bool True)]
    }
        key = secret "secret-key"
        t   = encodeSigned HS256 key cs
    iss' @=? tokenIssuer t

case_encodeDecodeJWTClaimsSetCustomClaims = do
    let now = 1234
        cs = def {
        iss = stringOrURI "Foo"
      , iat = intDate now
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", Bool True)]
    }
    let secret' = secret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned HS256 secret' cs
    Just cs @=? fmap claims jwt

case_encodeDecodeJWTClaimsSetWithSingleAud = do
    let now = 1234
        cs = def {
            iss = stringOrURI "Foo"
          , aud = Left <$> stringOrURI "single-audience"
          , iat = intDate now
        }
    let secret' = secret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned HS256 secret' cs
    Just cs @=? fmap claims jwt

case_encodeDecodeJWTClaimsSetWithMultipleAud = do
    let now = 1234
        cs = def {
            iss = stringOrURI "Foo"
          , aud = Right <$> (:[]) <$> stringOrURI "audience"
          , iat = intDate now
        }
    let secret' = secret "secret"
        jwt = decodeAndVerifySignature secret' $ encodeSigned HS256 secret' cs
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

prop_encode_decode_prop = f
    where f :: JWTClaimsSet -> Bool
          f claims' = let Just unverified = (decode $ encodeSigned HS256 (secret "secret") claims')
                      in claims unverified == claims'

prop_encode_decode_verify_signature_prop = f
    where f :: JWTClaimsSet -> Bool
          f claims' = let key = secret "secret"
                          Just verified = (decodeAndVerifySignature key $ encodeSigned HS256 key claims')
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

type ClaimsMap = Map.Map T.Text Value
instance Arbitrary ClaimsMap where
    arbitrary = return Map.empty

instance Arbitrary IntDate where
    arbitrary = fmap (f . intDate) (arbitrary :: QC.Gen NominalDiffTime)
        where f = fromMaybe (fromJust $ intDate 1)

instance Arbitrary NominalDiffTime where
    arbitrary = arbitrarySizedFractional
    shrink    = shrinkRealFrac

instance Arbitrary StringOrURI where
    arbitrary = fmap (f . stringOrURI) (arbitrary :: QC.Gen T.Text)
        where
            f = fromMaybe (fromJust $ stringOrURI "http://example.com")

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
