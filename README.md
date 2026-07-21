# MihomoADRules

This repository publishes rule artifacts through both GitHub Releases and the `release` branch.

## Branch Roles

- `main`: source branch that keeps the workflow, build script, and configuration.
- `release`: artifact branch that only contains published files for CDN access.

## Published Files

- `ads.txt`
- `ads.mrs`
- `metadata.json`

## Download URLs

- GitHub Release latest: `https://github.com/KawaiiSh1zuku/MihomoADRules/releases/latest/download/ads.mrs`
- Raw release branch: `https://raw.githubusercontent.com/KawaiiSh1zuku/MihomoADRules/release/ads.mrs`
- jsDelivr CDN: `https://cdn.jsdelivr.net/gh/KawaiiSh1zuku/MihomoADRules@release/ads.mrs`

## Notes

- Scheduled builds run from the default branch workflow and build directly from `main`.
- After each build, artifacts are uploaded to GitHub Release and force-pushed to the `release` branch.
- The workflow purges jsDelivr so the CDN can refresh quickly.
