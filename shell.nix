{ pkgs ? import <nixpkgs> {} }:
let
  m = pkgs.mda-lite.overrideAttrs (oa: {
    src = ./.;
  });
in
    m
