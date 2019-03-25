# 2019-03-25 0.10.0

* Add "kid" and allow specifying JOSEHeader
* Clean up docs and remove confusing JSON type alias

# 2018-01-04 0.9.0

* Switch from RSA and HsOpenSSL to x509-store
* Add Semigroup instances for GHC 8.6 compatibility

# 2018-03-21 0.8.0

* Support RS256 algorithm
* Add Monoid for ClaimsMap

Thanks to Patrick Brisbin and Brian McKenna for adding support for RS256.

# 2016-06-02 0.7.2

* Add missing Data.ByteString.ExtendedTests (Thanks to nomeata for reporting
  this).
* Support GHC 8 by raising the upper bound of base (GHC8 ships with base-4.9)
  (Thanks to Utku Demir).

# 2016-04-11 0.7.1

* Add `binarySecret` function to enable providing a secret based on a `ByteString`
  (fixes #21 - Thanks to Joe Nelson for reporting this).

# 2016-02-20 0.7.0

* Update JWT to match RFC 7519. This is a backward compatible change with
deprecation warnings added for types and functions to be removed in the
future.
	* Add NumericDate as a replacement for IntDate (and numericDate as a 
	  replacement for intDate)
	* Add JOSEHeader as a replacement for JWTHeader.
* Use Stack and LTS 4.0
* Use cryptonite instead of cryptohash (Thanks to Greg V)
* Remove Web.Base64 in favour of using `memory` (Thanks to Greg V)

# 2015-04-22 0.6.0

* Execute doctests in addition to the testsuite when using 'make test'.
* Export `ClaimsMap` type alias (fixes #12)
* Allow base 4.8
* Lowered required cabal library version (to 1.16) to workaround build
  issues in a consumer project.
* Add 7.10.1 to the travis config

# 2015-01-19 0.5.3

* Add the missing `other-modules` field to the .cabal file so that 
  all the tests are present in the source distribution. Thanks to 
  Richard Wallace for reporting this.

# 2015-01-17 0.5.2

* Tim McLean pointed out that comparing signatures may be susceptible to
  a timing attack in the way the signatures were compared (using the default
  Eq instance). Both `Signature` and `Secret` now have an `Eq` instance that
  uses a constant time comparison function. Thanks Tim for reporting this.

# 2015-01-03 0.5.1

* Fix the encoding of the `aud` part of the claim.
  Thanks to Aaron Levin for reporting and implementing the change.
  In addition to the fix we now also verify the shape fo the generated
  payload.

# 2014-12-01 0.5.0

* Rev. 17 of the JWT Draft changed the audience claim from being an
  optional String to being either an optional `StringOrURI`s or an optional list of
  `StringOrURI`s. Thanks to Aaron Levin for reporting and implementing the
  change. This change breaks backwards compatibility (in regard to 0.4.x).

# 2014-10-15 0.4.2

* Fix the build problems introduced in 0.4.1 to work with the 
  split network package. Thanks to Richard Wallace for
  fixing this and to Jeremy Shaw for reporting this at the same time.

# 2014-09-17 0.4.1

* Update jwt.cabal to work with the new split network package.
  Thanks to Jeremy Shaw for reporting this.

# 2014-08-02 0.4.0

* Change the upper boundary of base from 4.7 to 4.8 (#5)

# 2014-06-02 0.3.0

* Add verify function (thanks to Robert Massaioli) to allow verifying an
  already decoded JWT token

# 2014-03-10 0.2.1

* Add Decoding/Encoding sections
* Make the examples runnable by doctest
* Fix hlint warnings
* Add 'secondsSinceEpoch' to extract the seconds from epoch from an IntDate

# 2014-03-10 0.2.0

* Export the IntDate and StringOrURI types #5a1137b

# 2014-03-03  0.1.1

* Verify that invalid input to the decode\* functions fails as expected

# 2014-03-03  0.1.0

* Initial release
