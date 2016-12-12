# Haskell JSON Web Token (JWT)

JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred between two parties.

From http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

> JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred 
> between two parties. The claims in a JWT are encoded as a JavaScript Object Notation (JSON) 
> object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext 
> of a JSON Web Encryption (JWE) structure, enabling the claims to be digitally signed or MACed 
> and/or encrypted.

See the [Web.JWT module](http://hackage.haskell.org/package/jwt/docs/Web-JWT.html) documentation to get started.

[![Build
Status](https://travis-ci.org/juretta/haskell-jwt.svg?branch=master)](https://travis-ci.org/juretta/haskell-jwt)