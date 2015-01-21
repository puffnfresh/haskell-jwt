# You will need to extend this if your cabal build depends on non
# haskell files (here '.lhs' and '.hs' files).
SOURCE = $(shell find src -name '*.lhs' -o -name '*.hs')

.PHONY: clean build

dev: $(SOURCE)
			cabal install
setup:
			cabal sandbox init
			cabal install --only-dependencies --enable-tests


compile:
			cabal build

build: clean
			cabal build


clean:
			cabal clean

dependencies:
			cabal install --only-dependencies

test-setup:
			cabal install --only-dependencies --enable-tests --flags=doctests

test-compile: 
			cabal configure --enable-tests --flags=doctests
			cabal build

test: test-compile
			cabal test --show-details=always

doctest:
			@(doctest -XOverloadedStrings $(SOURCE))


