# User Authentication Enclave

An enclave that protects the pepper used to create [Argon2][argon2] password hashes.

[argon2]: https://en.wikipedia.org/wiki/Argon2

## Setup

In order to proceed, one needs to have the `poetry` dependency management and
packaging tool installed. Unless a recent version is available via your OS
package manager, as it would be on Arch Linux and friends :), the recommended
means of installing `poetry` is via the `pipx` tool as described in [their
documentation][pipx-install].

Once `pipx` is installed, installing `poetry` is as simple as

```shell
pipx install --python3.10 poetry
```

If you are simply looking for the API docs you may now skip ahead to the
[following section][#quick-start], you should also install the `pyenv` tool as
it is invaluable in managing your project-specific and shell-specific virtual
environments. This is again as simple as

```shell
pipx install --python3.10 pyenv
```

If you use `bash` as your shell then copy the following to your
`~/.bash_profile`, if it exists, or otherwise to `~/.profile`

```bash
# you may ignore this line if it is already set in your config
export XDG_DATA_HOME="$HOME/.local/share"

export PYENV_ROOT="$XDG_DATA_HOME/pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

and copy the same last line to your `~/.bashrc`

```bash
eval "$(pyenv init -)"
```

Make sure to log out (and back in of course) or, alternatively, restart your
machine. Once you are back in the `app` sub-directory of the
project run

```shell
pyenv local 3.{10,11}
```

[pipx-install]: https://python-poetry.org/docs/#installation

## Quick Start

In the root of the Python project, where the `pyproject.toml` is located, run
the following command:

```shell
poetry install
```

Make sure the following environment variables have been set in your local `.env` file:

- `ENCLAVE_SHARED_OBJECT="../build/bin/enclave/signed.so"`
- `SGX_DEBUG_MODE=1`

Note that `poetry` creates and keeps track of project-related `python` virtual
environments on your behalf via your IDE (an IDE plugin might be necessary) or
from the command line. Run

```shell
poetry env info
```

for details about available environments for your current project. If you would
like to spawn a shell inside the current `poetry` virtual environment this may
be done via

```shell
poetry shell
```
