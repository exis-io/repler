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

# Security

By design, the repler enables execution of untrusted code.  We have
followed best practices for ensuring the integrity and security of the
host machine, including the following measures.

* Stripping SETUID bits from executables in the base images.
* Setting resource limits (CPU time, memory, and number of open files).
* Dropping down to an unprivileged user before executing the code.

It is highly recommended that you run an up-to-date version of Linux
and Docker and that you isolate the repler from other services on your
network.
