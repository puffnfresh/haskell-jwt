module Data.ByteString.Extended (
    module Data.ByteString
  , constTimeCompare
) where

import           Data.Bits
import           Data.ByteString
import qualified Data.List       as L
import           Prelude         hiding (length, zip, zipWith)

constTimeCompare :: ByteString -> ByteString -> Bool
constTimeCompare l r = length l == length r && comp' l r
  where
    comp' a b = 0 == L.foldl' (.|.) 0 (uncurry xor <$> zip a b)
