{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Data.Text.ExtendedTests
  (
    main
  , defaultTestGroup
) where

import           Data.String           (fromString)
import qualified Data.Text.Extended    as T
import qualified Test.QuickCheck       as QC
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

prop_constTimeCompare :: T.Text -> T.Text -> Bool
prop_constTimeCompare a b = (a == b) == (a `T.constTimeCompare` b)

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

