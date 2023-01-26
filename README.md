# Nautilus Enclaves

A collection of SGX enclaves utilized in products by Nautilus,
as well as Python wrappers to access them.

For the Python part, we use [Poetry] for package management.
On the Debian family of OSes, install it so:

```
apt install python3-poetry
```

Proceed by navigating to a directory containing pyproject.toml,
then use `poetry` to install some needed packages:

```
cd $enclave/app
poetry install
```

Navigate back to the relevant enclave project directory,
and create a .env file indicating that this is just a simulation:

```
cd ..
echo 'export SGX_DEBUG_MODE=1' > .env
```

Then, finally, build the project:

```
make
````

[Poetry]: https://python-poetry.org
