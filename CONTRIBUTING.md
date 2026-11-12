# Contributing

Thanks for helping improve the detections.ai examples.

## Reporting a problem

Open an issue that names the example, what you ran, and what happened. Leave out API keys, tenant IDs and other secrets.

To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Proposing a change

1. Fork the repository and create a branch.
2. Make your change. Each example lives in its own folder with a README that explains how to deploy it.
3. If you change a `main.bicep`, rebuild its `azuredeploy.json` with `az bicep build --file main.bicep` so the Deploy to
   Azure button matches.
4. Open a pull request and fill in the template.

A detections.ai maintainer reviews every pull request and merges it. GitHub Actions workflows on pull requests from
forks run only after a maintainer approves them.

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
