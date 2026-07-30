{
  description = "TS + tsx starter";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nodejs_24
            gcc
          ];

          shellHook = ''
            export PATH="$PWD/node_modules/.bin:$PATH"

            if [ ! -d node_modules ]; then
              npm install
            fi
          '';
        };
      });
}
