{
  description = "RustDesk server development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable."1.82.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "rustdesk-server";

          nativeBuildInputs = with pkgs; [
            rustToolchain
            cargo-watch
            cargo-edit
            pkg-config
            cmake
            git
            sqlite
          ];

          buildInputs = with pkgs; [
            libsodium
            openssl
            zstd
            dnsutils
          ];

          SQLX_OFFLINE = "true";

          shellHook = ''
            echo "RustDesk server dev shell"
            echo "  Rust: $(rustc --version)"
            echo "  cargo build"
            echo "  cargo run --bin hbbs"
            echo "  cargo run --bin hbbr"
            echo "  git submodule update --init --recursive"
          '';
        };
      }
    );
}
