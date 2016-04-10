module Main where

import qualified Web.JWTTests
import qualified Web.JWTTestsCompat
import qualified Web.JWTInteropTests
import qualified Data.ByteString.ExtendedTests
import qualified Data.Text.ExtendedTests
import           Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "JWT Tests" [
                    Web.JWTTests.defaultTestGroup
                  , Web.JWTTestsCompat.defaultTestGroup
                  , Web.JWTInteropTests.defaultTestGroup
                  , Data.Text.ExtendedTests.defaultTestGroup
                  , Data.ByteString.ExtendedTests.defaultTestGroup
                ]

