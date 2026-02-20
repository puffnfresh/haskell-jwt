import System.Exit (exitWith)
import System.Process (system)

main :: IO ()
main = do
  exitWith =<< system "cabal repl --with-ghc=doctest"
  -- See README of doctest https://hackage.haskell.org/package/doctest
