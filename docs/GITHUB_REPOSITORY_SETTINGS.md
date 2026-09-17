# Recommended GitHub repository settings

This is a small project. Keep repository features focused.

## Keep enabled

- **Issues** - bug reports and feature requests
- **Pull requests** - contributions and review
- **Actions** - CI from `.github/workflows/ci.yml`
- **Security** features available to the repository
- **Private vulnerability reporting** if available

## Keep disabled initially

- **Wiki** - documentation belongs in the versioned `README.md` and `docs/` directory
- **Projects** - unnecessary until there is enough work to justify a board
- **Discussions** - unnecessary while Issues are sufficient for bugs/features/questions

## Suggested merge settings

For a one-maintainer project:

- allow **squash merging**;
- optionally disable merge commits/rebase if you want one consistent history style;
- automatically delete head branches after pull requests are merged;
- require CI to pass before merging once the repository is established.

Do not add branch-protection complexity merely for appearance. Add it when outside contributors or automation make accidental direct changes a realistic risk.
