{-# LANGUAGE OverloadedStrings #-}

module Data.Text.Additions (
    constTimeCompare
) where

import           Control.Applicative ((<$>))
import           Data.Bits
import           Data.Char
import           Data.Function       (on)
import           Data.List           (foldl')
import qualified Data.Text           as T

constTimeCompare :: T.Text -> T.Text -> Bool
constTimeCompare l r = T.length l == T.length r && comp' l r
  where
    comp' a b = 0 == foldl' (.|.) 0 (uncurry (on xor ord) <$> T.zip a b)
