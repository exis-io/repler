The repler enables websites to host executable code samples in a variety
of languages.  The currently supported languages are JS, Python, and
Swift.  The repler uses Docker containers with strict resource limits
to execute the code and a websocket connection to stream messages back
to the user.

# Example

![animated example](https://github.com/exis-io/repler/raw/master/example.gif)

# Requirements

* Docker >= 1.6.2 (Recommended: https://docs.docker.com/engine/installation/linux/ubuntulinux/)
* docker-compose (https://docs.docker.com/compose/install/)

# Installation

1. Build the base images.

    ```bash
    make --directory=images
    ```

2. Launch the repler.

    ```bash
    docker-compose up
    ```
