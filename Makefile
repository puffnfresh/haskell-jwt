doctests:
	stack test jwt:doctests

clean:
	stack clean

test-dist:
	stack sdist && mkdir temp && tar -xf `stack path --dist-dir`/*.tar.gz -C ./temp && cd temp && stack init && stack test

.PHONY: clean doctests
