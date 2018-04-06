{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Data.ByteString.ExtendedTests
  (
    main
  , defaultTestGroup
) where

import qualified Data.ByteString.Extended as BS
import qualified Test.QuickCheck          as QC
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

prop_constTimeCompare :: BS.ByteString -> BS.ByteString  -> Bool
prop_constTimeCompare a b = (a == b) == (a `BS.constTimeCompare` b)

instance Arbitrary BS.ByteString where
    arbitrary = BS.pack <$> arbitrary
    shrink xs = BS.pack <$> shrink (BS.unpack xs)
