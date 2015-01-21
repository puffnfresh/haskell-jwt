import           Test.DocTest

main :: IO ()
main = doctest ["-XOverloadedStrings", "-isrc", "src/Web/JWT.hs"]
