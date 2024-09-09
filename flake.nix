{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, self }:
    let forEachSystem = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in {
      devShells = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          jwt =
            { mkDerivation, aeson, base, bytestring, containers, crypton
            , crypton-x509, crypton-x509-store, cryptostore, doctest
            , http-types, HUnit, lens, lens-aeson, lib, memory, network-uri
            , QuickCheck, scientific, semigroups, tasty, tasty-hunit
            , tasty-quickcheck, tasty-th, text, time, unordered-containers
            , vector
            }:
            mkDerivation {
              pname = "jwt";
              version = "0.11.0";
              src = ./.;
              libraryHaskellDepends = [
                aeson base bytestring containers crypton crypton-x509
                crypton-x509-store cryptostore http-types memory network-uri
                scientific semigroups text time unordered-containers vector
              ];
              testHaskellDepends = [
                aeson base bytestring containers crypton crypton-x509
                crypton-x509-store cryptostore doctest http-types HUnit lens
                lens-aeson memory network-uri QuickCheck scientific semigroups
                tasty tasty-hunit tasty-quickcheck tasty-th text time
                unordered-containers vector
              ];
              homepage = "https://github.com/puffnfresh/haskell-jwt";
              description = "JSON Web Token (JWT) decoding and encoding";
              license = lib.licenses.mit;
            };
        in {
          default =
            (pkgs.haskellPackages.override {
              overrides = self: super: {
                cryptostore = pkgs.haskell.lib.addBuildDepends (pkgs.haskell.lib.enableCabalFlag super.cryptostore "use_crypton") [
                  self.crypton
                  self.crypton-x509
                  self.crypton-x509-validation
                ];
              };
            }).shellFor {
              packages = p: [ (p.callPackage jwt { }) ];
              buildInputs = [ pkgs.cabal-install ];
            };
        });
    };
}
