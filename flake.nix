{
  description = "A devShell example";
  inputs = {
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };
  outputs = {
    self,
    nixpkgs,
    crane,
    flake-utils,
    fenix,
    advisory-db,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [fenix.overlays.default];
      };
      inherit (pkgs) lib;

      rustToolchain = pkgs.fenix.combine (with pkgs.fenix; [
        stable.cargo
        stable.clippy
        stable.rustc
        latest.rustfmt
      ]);

      craneLib = (crane.mkLib pkgs).overrideToolchain (p: rustToolchain);
      craneDev = craneLib.overrideToolchain (p:
        p.fenix.combine (with p.fenix.stable; [
          rustToolchain
          rust-analyzer
          rust-src
        ]));

      craneNightly = craneLib.overrideToolchain pkgs.fenix.minimal.toolchain;

      root = ./.;
      src = lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions [
          (craneLib.fileset.commonCargoSources ./.)
          (lib.fileset.fileFilter (file: file.hasExt "proto") ./crates/proto/proto)

          # (lib.fileset.maybeMissing ./migrations)
          # (lib.fileset.maybeMissing ./.sqlx)
          (lib.fileset.maybeMissing ./rustfmt.toml)
        ];
      };

      rustHostPlatform = pkgs.hostPlatform.rust.rustcTarget;

      # Common arguments can be set here to avoid repeating them later
      commonArgs = {
        inherit src;
        strictDeps = true;

        buildInputs = with pkgs;
          [
            nettle
            gmp
          ]
          ++ lib.optionals stdenv.isDarwin [];

        nativeBuildInputs = with pkgs; [
          protobuf
          pkg-config
          llvmPackages.clangUseLLVM
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      };

      mkCargoArtifacts = craneLib: craneLib.buildDepsOnly commonArgs;

      mkIndividualCrateArgs = craneLib:
        commonArgs
        // {
          cargoArtifacts = mkCargoArtifacts craneLib;
          inherit (craneLib.crateNameFromCargoToml {inherit src;}) version;
          # NB: we disable tests since we'll run them all via cargo-nextest
          doCheck = false;
        };

      fileSetForCrate = crate: fs:
        lib.fileset.toSource {
          inherit root;
          fileset = lib.fileset.unions ([
              ./Cargo.toml
              ./Cargo.lock

              (craneLib.fileset.commonCargoSources ./crates/proto)
              (lib.fileset.fileFilter (file: file.hasExt "proto") ./crates/proto/proto)

              (craneLib.fileset.commonCargoSources crate)
              # (lib.fileset.maybeMissing (crate + /.sqlx))
              # (lib.fileset.maybeMissing (crate + /migrations))
            ]
            ++ fs);
        };

      mkPackage = craneLib: name:
        craneLib.buildPackage (mkIndividualCrateArgs craneLib
          // {
            pname = "runemail-${name}";
            cargoExtraArgs = "-p runemail-${name}";

            src = fileSetForCrate ./crates/${name} [];
          });

      mkPackages = craneLib: {
        runemail-wks = mkPackage craneLib "wks";
      };

      mkImage = name: pkg:
        pkgs.dockerTools.buildLayeredImage {
          name = name;
          tag = "latest";
          contents = [pkg];
          config = {
            Cmd = ["${pkg}/bin/${name}"];
          };
        };

      mkChecks = craneLib: let
        cargoArtifacts = mkCargoArtifacts craneLib;
      in {
        # Run clippy
        workspace-clippy = craneLib.cargoClippy (commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

        # Check formatting
        workspace-fmt = craneLib.cargoFmt {
          inherit src;
        };

        # Audit dependencies
        workspace-audit = craneLib.cargoAudit {
          inherit src advisory-db;
        };

        # Audit licenses
        workspace-deny = craneLib.cargoDeny {
          inherit src;
        };

        # Run tests with cargo-nextest
        # Consider setting `doCheck = false` on other crate derivations
        # if you do not want the tests to run twice
        workspace-nextest = craneLib.cargoNextest (commonArgs
          // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
            cargoNextestPartitionsExtraArgs = "--no-tests=pass";
          });
      };

      packages = mkPackages craneLib;
      dockerImages = lib.mapAttrs mkImage packages;
    in {
      checks =
        mkChecks craneLib
        // packages;
      packages =
        {
          default = packages.runemail;
          dockerImages = pkgs.linkFarm "docker-images" (pkgs.lib.mapAttrsToList
            (name: image: {
              name = name;
              path = image;
            })
            dockerImages);
        }
        // (lib.mapAttrs' (name: value: {
            name = "${name}-docker";
            value = value;
          })
          dockerImages)
        // packages;
      apps.default = flake-utils.lib.mkApp {
        drv = packages.runemail;
      };

      devShells.default = craneDev.devShell {
        checks = (mkChecks craneDev) // mkPackages craneDev;

        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.llvmPackages.clangUseLLVM}/bin/clang";
        CARGO_ENCODED_RUSTFLAGS = "-Clink-arg=-fuse-ld=${pkgs.mold}/bin/mold";
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath commonArgs.buildInputs;
        packages = with pkgs; [
          patchelf
          grpcurl
          sqlx-cli
        ];
      };
    });
}
