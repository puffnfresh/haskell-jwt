{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-|
Tests that verify that the shape of the JSON used is matching the spec.

It's not sufficient to just ensure that

`fromJSON . toJSON = id`

This would only verify that an isomorphism exists but wouldn't test the specific shape we expect.

While the above would be sufficent if the haskell-jwt library would be used on the sender and receiver side,
interoperability couldn't be guaranteed. We need to ensure that the JSON conforms to the spec so that every
JWT compliant library can decode it.
-}
module Web.JWTInteropTests (
    main
  , defaultTestGroup
) where

import           Prelude hiding (exp)
import           Control.Lens
import           Data.Aeson.Lens
import           Data.Aeson.Types
import qualified Data.Map              as Map
import           Data.Maybe
import           Data.String           (fromString)
import qualified Data.Text             as T
import qualified Data.Text.Lazy        as TL
import           Data.Time
import qualified Data.Vector           as Vector
import qualified Test.QuickCheck       as QC
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH
import           Web.JWT

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

prop_encode_decode_jti :: JWTClaimsSet -> Bool
prop_encode_decode_jti = shouldBeMaybeStringOrUri "jti" jti

prop_encode_decode_sub :: JWTClaimsSet -> Bool
prop_encode_decode_sub = shouldBeMaybeStringOrUri "sub" sub

prop_encode_decode_iss :: JWTClaimsSet -> Bool
prop_encode_decode_iss = shouldBeMaybeStringOrUri "iss" iss

shouldBeMaybeStringOrUri :: ToJSON a => T.Text -> (a -> Maybe StringOrURI) -> a -> Bool
shouldBeMaybeStringOrUri key' f claims' = 
    let json = toJSON claims' ^? key key'
    in json == (fmap (String . stringOrURIToText) $ f claims')

prop_encode_decode_aud :: JWTClaimsSet -> Bool
prop_encode_decode_aud claims' =
    let json = toJSON claims' ^? key "aud"
    in json == (case aud claims' of
                      Just (Left s)   -> Just $ String $ stringOrURIToText s                                    -- aud is just a single element
                      Just (Right xs) -> Just $ Array $ fmap (String . stringOrURIToText) $ Vector.fromList xs  -- aud is a list of elements
                      Nothing         -> Nothing                                                                -- aud is absent
               )

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

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

instance Arbitrary TL.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)
