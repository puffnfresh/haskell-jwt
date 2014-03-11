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
import qualified Data.Aeson            as JSON
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
    (Just str) @=? (fmap (T.pack . show) sou)

case_stringOrURI= do
    let str = "http://user@example.com:8900/foo/bar?baz=t;"
        sou = stringOrURI str
    (Just str) @=? (fmap (T.pack . show) sou)

case_decodeJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decode input
    True @=? isJust mJwt
    True @=? (isJust $ fmap signature mJwt)
    let (Just unverified) = mJwt
    (Just HS256) @=? (alg $ header unverified)
    (Just "payload") @=? (Map.lookup "some" $ unregisteredClaims $ claims unverified)

case_decodeAndVerifyJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decodeAndVerifySignature (secret "secret") input
    True @=? isJust mJwt
    let (Just verified) = mJwt
    (Just HS256) @=? (alg $ header verified)
    (Just "payload") @=? (Map.lookup "some" $ unregisteredClaims $ claims verified)

case_decodeAndVerifyJWTFailing = do
    -- Generated with ruby-jwt, modified to be invalid
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2u"
        mJwt = decodeAndVerifySignature (secret "secret") input
    False @=? isJust mJwt

case_decodeInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map decode inputs
    True @=? (all isNothing result)

case_decodeAndVerifySignatureInvalidInput = do
    let inputs = ["", "a.", "a.b"]
        result = map (decodeAndVerifySignature (secret "secret")) inputs
    True @=? (all isNothing result)

case_encodeJWTNoMac = do
    let cs = def {
        iss = stringOrURI "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        jwt = encodeUnsigned cs
    -- Verified using https://py-jwt-decoder.appspot.com/
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0." @=? jwt

case_encodeDecodeJWTNoMac = do
    let cs = def {
        iss = stringOrURI "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        mJwt = decode $ encodeUnsigned cs
    True @=? (isJust mJwt)
    let (Just unverified) = mJwt
    cs @=? claims unverified

case_encodeDecodeJWT = do
    let now = 1394573404
        cs = def {
        iss = stringOrURI "Foo"
      , iat = intDate now
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        key = secret "secret-key"
        mJwt = decode $ encodeSigned HS256 key cs
    True @=? (isJust mJwt)
    let (Just unverified) = mJwt
    cs @=? claims unverified
    Just now @=? fmap secondsSinceEpoch (iat (claims unverified))

case_tokenIssuer = do
    let iss' = stringOrURI "Foo"
        cs = def {
        iss = iss'
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        key = secret "secret-key"
        t   = encodeSigned HS256 key cs
    iss' @=? tokenIssuer t


case_encodeJWTClaimsSet = do
    let cs = def {
        iss = stringOrURI "Foo"
    }
    -- This is a valid JWT string that can be decoded with the given secret using the ruby JWT library
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJGb28ifQ.dfhkuexBONtkewFjLNz9mZlFc82GvRkaZKD8Pd53zJ8" @=? encodeSigned HS256 (secret "secret") cs

case_encodeJWTClaimsSetCustomClaims = do
    let now = 1234
        cs = def {
        iss = stringOrURI "Foo"
      , iat = intDate now
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
    -- The expected string can be decoded using the ruby-jwt library
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjEyMzQsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJGb28ifQ.F3VCSxBBnY2caX4AH4GvIHyTVUhOnJF9Av_G_N4m710" @=? encodeSigned HS256 (secret "secret") cs


prop_stringOrURIProp = f
    where f :: StringOrURI -> Bool
          f sou = let s = stringOrURI $ T.pack $ show sou
                  in (Just sou) == s

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
        where f mIntDate = fromMaybe (fromJust $ intDate 1) mIntDate

instance Arbitrary NominalDiffTime where
    arbitrary = arbitrarySizedFractional
    shrink    = shrinkRealFrac

instance Arbitrary StringOrURI where
    arbitrary = fmap (f . stringOrURI) (arbitrary :: QC.Gen T.Text)
        where
            f mSou = fromMaybe (fromJust $ stringOrURI "http://example.com") mSou

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
