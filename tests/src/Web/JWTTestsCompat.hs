{-# LANGUAGE BangPatterns, OverloadedStrings, ScopedTypeVariables, TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{- 
- Turn of deprecation warnings as these tests deliberately use 
- deprecated types/functions to ensure that the library is backward compatible 
-}
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

module Web.JWTTestsCompat
  (
    main
  , defaultTestGroup
) where

import           Test.Tasty
import           Test.Tasty.TH
import           Test.Tasty.HUnit
import qualified Data.Map              as Map
import           Data.Aeson.Types
import           Web.JWT

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

case_intDateDeriveOrd = do
    let i1 = intDate 1231231231 -- Tue  6 Jan 2009 19:40:31 AEDT
        i2 = intDate 1231232231 -- Tue  6 Jan 2009 19:57:11 AEDT
    LT @=? i1 `compare` i2

case_encodeDecodeJWTIntDateIat = do
    let now = 1394573404
        cs = mempty {
        iss = stringOrURI "Foo"
      , iat = intDate now
      , unregisteredClaims = ClaimsMap $ Map.fromList [("http://example.com/is_root", Bool True)]
    }
        key = hmacSecret "secret-key"
        mJwt = decode $ encodeSigned key mempty cs
    let (Just claims') = fmap claims mJwt
    cs @=? claims'
    Just now @=? fmap secondsSinceEpoch (iat claims')

