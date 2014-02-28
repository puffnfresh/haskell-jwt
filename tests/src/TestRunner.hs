module Main where

import qualified Web.JWTTests
import           Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "JWT Tests" [
                    Web.JWTTests.defaultTestGroup
                ]

