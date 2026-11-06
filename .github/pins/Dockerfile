# Never built. Each line pins an image the project runs from somewhere Dependabot doesn't read
# (a compose anchor, a shell variable, a workflow literal), so Dependabot's docker entry reads it
# here instead (register D-162). Its pull request bumps only this file, and
# tests/unit/test_deploy.py::test_every_image_pin_matches_the_stub then names each copy to change
# in the same pull request. One stage per image; the stage name is how the test finds it.

# deploy/compose.yaml, deploy/compose.hardened.yaml and examples/existing-stack/compose.yaml.
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f AS caddy
# scripts/smoke-image.sh (contract 51's Squid; ci.yml pulls it from there).
FROM ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c AS squid
# .github/actions/build-image/action.yml and ci.yml's reproducible build.
FROM moby/buildkit:v0.34.1@sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c AS buildkit
# .github/actions/build-image/action.yml.
FROM docker/buildkit-syft-scanner:1.12.0@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9 AS syft
FROM anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe AS grype
# .github/workflows/release.yml.
FROM quay.io/skopeo/stable:v1.22.3-immutable@sha256:c0ee1f4edca5c01cb8d5611124f92f3cc47196ecab68aee5d0f90834e00574d5 AS skopeo
