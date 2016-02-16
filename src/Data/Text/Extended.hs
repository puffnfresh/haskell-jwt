{-# LANGUAGE OverloadedStrings #-}

module Data.Text.Extended (
    module Data.Text
  , constTimeCompare
) where

import           Data.Bits
import           Data.Char
import           Data.Function       (on)
import qualified Data.List           as L
import           Data.Text
import           Prelude             hiding (length, zip)

constTimeCompare :: Text -> Text -> Bool
constTimeCompare l r = length l == length r && comp' l r
  where
    comp' a b = 0 == L.foldl' (.|.) 0 (uncurry (on xor ord) <$> zip a b)
