{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
module Data.Text.AdditionsTests
  (
    main
  , defaultTestGroup
) where

import           Control.Applicative
import           Data.String           (fromString)
import qualified Data.Text             as T
import           Data.Text.Additions
import qualified Test.QuickCheck       as QC
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

defaultTestGroup :: TestTree
defaultTestGroup = $(testGroupGenerator)

main :: IO ()
main = defaultMain defaultTestGroup

prop_constTimeCompare :: T.Text -> T.Text -> Bool
prop_constTimeCompare a b = (a == b) == (a `constTimeCompare` b)

instance Arbitrary T.Text where
    arbitrary = fromString <$> (arbitrary :: QC.Gen String)

