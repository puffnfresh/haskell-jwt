module Main where

import qualified Web.JWTTests
import qualified Web.Base64Tests
import qualified Data.Text.AdditionsTests
import           Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "JWT Tests" [
                    Web.JWTTests.defaultTestGroup
                  , Web.Base64Tests.defaultTestGroup
                  , Data.Text.AdditionsTests.defaultTestGroup
                ]

