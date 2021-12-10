all: setup test doctests

doctests:
	stack test jwt:doctests

setup:
	stack setup

test:
	stack test

test-dist:
	stack sdist && mkdir temp && tar -xf `stack path --dist-dir`/*.tar.gz -C ./temp && cd temp && stack setup && stack test && stack test jwt:doctests

clean:
	stack clean

.PHONY: all clean doctests setup test test-dist
