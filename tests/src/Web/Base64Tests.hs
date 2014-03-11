{-# LANGUAGE BangPatterns, OverloadedStrings, ScopedTypeVariables, TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
module Web.Base64Tests
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
import           Web.Base64

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup



case_base64EncodeString = do
    let header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" @=? base64Encode header

case_base64EncodeStringNoPadding = do
    let header = "sdjkfhaks jdhfak sjldhfa lkjsdf"
    "c2Rqa2ZoYWtzIGpkaGZhayBzamxkaGZhIGxranNkZg" @=? base64Encode header

case_base64EncodeDecodeStringNoPadding = do
    let header = "sdjkfhaks jdhfak sjldhfa lkjsdf"
    header @=? base64Decode (base64Encode header)

case_base64DecodeString = do
    let str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}" @=? base64Decode str

prop_base64_encode_decode = f
    where f :: T.Text -> Bool
          f input = base64Decode (base64Encode input) == input


instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
