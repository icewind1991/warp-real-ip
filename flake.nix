{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-26.05";
    flakelight = {
      url = "github:nix-community/flakelight";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mill-scale = {
      url = "git+https://codeberg.org/icewind/mill-scale.git";
      inputs.flakelight.follows = "flakelight";
    };
  };
  outputs = {mill-scale, ...}: mill-scale ./. {};
}
