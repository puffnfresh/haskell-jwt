{-# LANGUAGE OverloadedStrings  #-}

module Web.Base64 (
    base64Encode
  , base64Encode'
  , base64Decode
  , removePaddingBase64Encoding
) where


import qualified Data.ByteString.Char8      as B
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE
import qualified Data.ByteString.Base64.URL as BASE64

base64Decode :: T.Text -> T.Text
base64Decode = operateOnText BASE64.decodeLenient

base64Encode :: T.Text -> T.Text
base64Encode = removePaddingBase64Encoding . operateOnText BASE64.encode

base64Encode' :: B.ByteString -> T.Text
base64Encode' = removePaddingBase64Encoding . TE.decodeUtf8 . BASE64.encode

removePaddingBase64Encoding :: T.Text -> T.Text
removePaddingBase64Encoding = T.dropWhileEnd (=='=')


operateOnText :: (B.ByteString -> B.ByteString) -> T.Text -> T.Text
operateOnText f = TE.decodeUtf8 . f . TE.encodeUtf8
