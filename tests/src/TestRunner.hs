module Main where

import qualified Web.JWTTests
import qualified Web.JWTInteropTests
import qualified Web.Base64Tests
import           Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "JWT Tests" [
                    Web.JWTTests.defaultTestGroup
                  , Web.JWTInteropTests.defaultTestGroup
                  , Web.Base64Tests.defaultTestGroup
                ]

