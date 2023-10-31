{
  description = "Kernel, Zig dev";

  inputs = {
    pkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    zig = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "pkgs";
    };
    zls = {
      url = "github:zigtools/zls";
      inputs.zig-overlay.follows = "zig";
    };
  };

  outputs = { self, pkgs, zig, zls }:
    let
      sys = "x86_64-linux";
    in
      with import pkgs { system = "${sys}"; config.allowUnfree = true; };
      {
        devShells.${sys}.default = mkShell {
          buildInputs = [
            zig.packages.${sys}.master
            zls.packages.${sys}.zls

            automake
            autoconf
            gnumake
            linuxHeaders

            bear
            bc
            bison
            flex
            gmp
            libmpc
            elfutils
            openssl
            zstd
            zlib
            mpfr
            rustc
            rust-bindgen
            binutils
            util-linux
            perl
            python311Full
            python311Packages.gmpy2
            pahole
            ncurses
            pkg-config
            cpio
            fuse3

            llvmPackages_16.clang-unwrapped
            llvmPackages_16.bintools-unwrapped
            clang-tools_16

            pwndbg
            ropgadget

            nsjail
            (busybox.override { enableAppletSymlinks = false; })
          ];
        };
      };
}
