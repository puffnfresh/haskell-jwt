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
import           Web.JWT

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup


case_decodeJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decode input
    True @=? isJust mJwt
    let (Just unverified) = mJwt
    (Just HS256) @=? (alg $ header unverified)
    (Just "payload") @=? (Map.lookup "some" $ unregisteredClaims $ claims unverified)

case_decodeAndVerifyJWT = do
    -- Generated with ruby-jwt
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"
        mJwt = decodeAndVerify (secret "secret") input
    True @=? isJust mJwt
    let (Just verified) = mJwt
    (Just HS256) @=? (alg $ header verified)
    (Just "payload") @=? (Map.lookup "some" $ unregisteredClaims $ claims verified)

case_decodeAndVerifyJWTFailing = do
    -- Generated with ruby-jwt, modified to be invalid
    let input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2u"
        mJwt = decodeAndVerify (secret "secret") input
    False @=? isJust mJwt

case_encodeDecodeJWT = do
    let cs = def {
        iss = Just "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        key = secret "secret-key"
        mJwt = decode $ encode key cs
    True @=? (isJust mJwt)
    let (Just unverified) = mJwt
    cs @=? claims unverified

case_tokenIssuer = do
    let cs = def {
        iss = Just "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
        key = secret "secret-key"
        t   = encode key cs
    Just "Foo" @=? tokenIssuer t


case_encodeJWTClaimsSet = do
    let cs = def {
        iss = Just "Foo"
    }
    -- This is a valid JWT string that can be decoded with the given secret using the ruby JWT library
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJGb28ifQ.dfhkuexBONtkewFjLNz9mZlFc82GvRkaZKD8Pd53zJ8" @=? encode (secret "secret") cs

case_encodeJWTClaimsSetCustomClaims = do
    let cs = def {
        iss = Just "Foo"
      , unregisteredClaims = Map.fromList [("http://example.com/is_root", (Bool True))]
    }
    -- The expected string can be decoded using the ruby-jwt library
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiRm9vIn0.UVp4TIg8-OmY_vNHbyxMPx7v0P6jCY4rqYVWVcjdXQk" @=? encode (secret "secret") cs

case_base64EncodeString = do
    let header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" @=? base64Encode header

case_base64EncodeStringNoPadding = do
    let header = "sdjkfhaks jdhfak sjldhfa lkjsdf"
    "c2Rqa2ZoYWtzIGpkaGZhayBzamxkaGZhIGxranNkZg" @=? base64Encode header

case_base64EncodeDecodeStringNoPadding = do
    let header = "sdjkfhaks jdhfak sjldhfa lkjsdf"
    header @=? (base64Decode $ base64Encode header)

case_base64DecodeString = do
    let str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}" @=? base64Decode str


prop_encode_decode_prop = f
    where f :: JWTClaimsSet -> Bool
          f claims' = let Just unverified = (decode $ encode (secret "secret") claims')
                      in claims unverified == claims'


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
    arbitrary = IntDate <$> (arbitrary :: QC.Gen Integer)

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
