# Setting up VSCode for Building Images in `nivola-registry.site05.nivolapiemonte.it`

This guide explains how to set up Visual Studio Code (VSCode) for compiling and building container images in the `nivola-registry.site05.nivolapiemonte.it` repository.

## Prerequisites

Before you begin, ensure you have the following tools installed on your system:

*   **Docker:** The build process relies on Docker to create containerized build environments and package the application into images.
    *   Installation guide: [Get Docker](https://docs.docker.com/get-docker/)
*   **GNU Make:** The project uses a `Makefile` to orchestrate build and packaging scripts.
    *   On **Linux**, `make` is often pre-installed. If not, you can usually install it using your distribution's package manager (e.g., `sudo apt-get install make` for Debian/Ubuntu, `sudo yum install make` for Fedora/CentOS).
    *   On **macOS**, `make` can be installed via Xcode Command Line Tools: `xcode-select --install`
    *   On **Windows**, you can install `make` via Chocolatey (`choco install make`) or by using Windows Subsystem for Linux (WSL).

## Building Images

This project uses `dapper`, a tool by Rancher, to ensure a consistent build environment. Dapper runs the build process inside a Docker container defined by `Dockerfile.dapper` in the repository root. The `Makefile` provides convenient targets for building and packaging the application components. The first time you run a `make` command that uses `dapper` (like `make package`), it will download the `dapper` executable if it's not already present in the project root.

To build the container images:

1.  **Open the integrated terminal in VSCode:** You can do this by going to "Terminal" > "New Terminal" in the VSCode menu or by using the shortcut (e.g., ``Ctrl+` ``).
2.  **Run the `make` commands:**
    *   To build all packages (controller, agent, and webhook):
        ```bash
        make package
        ```
    *   To build a specific package, you can use one of the following commands:
        ```bash
        make package-controller
        make package-agent
        make package-webhook
        ```
    *   The `Makefile` will automatically invoke `dapper` to execute the build scripts (located in the `scripts/` directory) within the defined Docker environment. The resulting container images will be available in your local Docker image registry.

    *   To clean the build artifacts, you can usually find a `clean` target in Makefiles, though it's not explicitly defined in the root `Makefile` for this project. The `dapper` environment handles build artifacts internally, and new builds will typically start fresh. If you need to free up space from old dapper images, you might need to prune your Docker system periodically (`docker system prune`).

## Go Development with VSCode

For developing the Go code within this project using VSCode, follow these recommendations:

1.  **Install the Go Extension:** If you haven't already, install the official Go extension for VSCode. You can find it in the Extensions view (Ctrl+Shift+X or Cmd+Shift+X) by searching for `Go`.
    *   [Go extension on VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=golang.Go)

2.  **Open the Project using the Workspace File:**
    *   The repository includes a VSCode workspace file: `vm-dhcp-controller.code-workspace`.
    *   It's recommended to open the project in VSCode by opening this file directly ("File" > "Open Workspace from File...").
    *   This workspace file contains predefined settings for the Go language server, such as the `goroot` and `alternateTools` paths, which can be helpful for a consistent development environment, especially if you have multiple Go versions or custom Go installations. The current settings are:
        ```json
        {
          "folders": [
            {
              "path": "."
            }
          ],
          "settings": {
            "go.useLanguageServer": true,
            "go.goroot": "/usr/local/go", // This might need adjustment if your Go installation is different
            "go.alternateTools": {
              "go": "/usr/local/go/bin/go" // This might need adjustment
            }
          }
        }
        ```
    *   **Note:** The `goroot` and `go.alternateTools.go` paths in the workspace settings are hardcoded to `/usr/local/go`. If your Go installation path is different (especially on Windows or if you installed Go via a package manager to a different location), you might need to adjust these paths in `.vscode/settings.json` within the workspace or let the Go extension auto-detect your Go path. Often, the Go extension can manage this automatically if these settings are removed from the `.code-workspace` file, or you can set them in your user-level VSCode settings.

3.  **Using Go Tools:** With the Go extension installed, you'll have access to features like IntelliSense, code navigation, formatting, linting, and debugging.
    *   The build process (via `make` and `dapper`) is separate from the local Go development environment setup. For building images, always use the `make` commands. For local development, testing, and running individual Go programs (e.g., `go run ./cmd/controller`), your local Go installation and the VSCode Go extension will be used.

## Optional: Using the VSCode Docker Extension

For easier management of Docker images and containers directly within VSCode, you might find the Docker extension helpful:

*   **Install the Docker Extension:** Search for `Docker` in the Extensions view (Ctrl+Shift+X or Cmd+Shift+X).
    *   [Docker extension on VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker)
*   **Features:** Once installed, this extension allows you to:
    *   View your local Docker images (including the ones you build with `make package`).
    *   View running containers.
    *   Start/stop containers.
    *   Access container logs.
    *   And more.

This can be a convenient way to inspect the images built by the project without needing to switch to a separate terminal for Docker commands.

## Advanced Optional: VSCode Dev Containers

For a more deeply integrated development environment where VSCode itself runs inside a container defined by your project, you can explore **VSCode Dev Containers (Remote - Containers)**.

*   **Install the Dev Containers Extension:** Search for `Dev Containers` in the Extensions view.
    *   [Dev Containers extension on VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
*   **Concept:** You can create a `.devcontainer/devcontainer.json` configuration file. This file can instruct VSCode to open the project in a container based on an existing Dockerfile (like `Dockerfile.dapper` or a new one derived from it) or a Docker image.
*   **Benefits:**
    *   Ensures that your development environment is identical to the build environment used by `dapper`.
    *   All necessary tools, Go versions, and dependencies are pre-installed in the container, simplifying setup for new contributors.
    *   VSCode settings and extensions can be pre-configured for the dev container.
*   **Consideration:** Setting up a `devcontainer.json` requires understanding how to configure it to work with the project's structure and build tools (like `dapper` and `make`). You could use `Dockerfile.dapper` as a starting point for your dev container definition.

This is an advanced setup and is not required to build or develop the project, but it can significantly streamline the development experience for complex projects.
