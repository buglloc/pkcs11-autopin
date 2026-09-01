{
  description = "PKCS#11 proxy library with automatic PIN entry";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

        pkcs11-autopin = pkgs.rustPlatform.buildRustPackage {
          pname = "pkcs11-autopin";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
          ];

          # The library will be installed to lib/
          postInstall = ''
            mkdir -p $out/lib/pkcs11
            mv $out/lib/libpkcs11_autopin.so $out/lib/pkcs11/

            # Create config directory structure
            mkdir -p $out/etc/pkcs11-autopin.pins

            # Install example config
            install -Dm644 ${./example-config.yaml} $out/share/pkcs11-autopin/example-config.yaml
          '';

          meta = with pkgs.lib; {
            description = "PKCS#11 proxy library with automatic PIN entry";
            homepage = "https://github.com/buglloc/pkcs11-autopin";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };
      in
      {
        packages = {
          default = pkcs11-autopin;
          pkcs11-autopin = pkcs11-autopin;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            rust-analyzer
            pkg-config
            # For testing with actual PKCS#11 providers
            opensc
            softhsm
          ];

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      }
    ) // {
      # NixOS module
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.pkcs11-autopin;
        in
        {
          options.services.pkcs11-autopin = {
            enable = lib.mkEnableOption "PKCS#11 auto-PIN proxy";

            backend = lib.mkOption {
              type = lib.types.str;
              default = "/usr/lib64/pkcs11/libtpm2_pkcs11.so";
              description = "Path to the backend PKCS#11 library";
            };

            debug = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Enable debug logging";
            };

            pins = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
              description = ''
                PIN values keyed by token label.
                Example: token "My TPM" -> key "My_TPM"
              '';
              example = {
                "My_TPM_Token" = "1234";
              };
            };
          };

          config = lib.mkIf cfg.enable {
            environment.etc = {
              "pkcs11-autopin.yaml".text = ''
                debug: ${lib.boolToString cfg.debug}
                backend: ${cfg.backend}
              '';
            } // lib.mapAttrs' (name: value: {
              name = "pkcs11-autopin.pins/${name}";
              value = {
                text = value;
                mode = "0600";
              };
            }) cfg.pins;

            environment.systemPackages = [ self.packages.${pkgs.system}.default ];
          };
        };
    };
}

