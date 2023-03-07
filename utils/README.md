# setup

For the Python part, we use [Poetry] for package management.

- On the Debian family of OSes, install it so:

  ```
  apt install python3-poetry
  ```

- Proceed by navigating to a directory containing pyproject.toml,
  then use `poetry` to install some needed packages:

  ```
  cd $enclave/app
  poetry install
  ```

- Navigate back to the relevant enclave project directory,
  and create a `.env` file indicating that this is just a simulation:

  ```
  cd ..
  echo 'export SGX_DEBUG_MODE=1' > .env
  ```

- While there,
  point to where the shared object is located:

  ```
  echo 'export ENCLAVE_SHARED_OBJECT=../build/bin/enclave.signed.so' >> .env
  ```

- Source the Intel SGX SDK env,
  created by following instructions from [this repo].

- Navigate to `app/`,
  then open the Python environment by running `poetry shell`.
  You will know this worked by seeing something similar to the following,
  after running each shell command:

  > (utils-py3.11)


# build

- Do it so:

  ```
  make
  ```

- To create the Python bindings:

  ```
  cd app
  maturin develop
  ```

  Note that `maturin` is installed in the Python env with `poetry install` above.

# test

Navigate to `app/`, run the Python shell, import `utils`, and play.

The following shows some examples:

```
$ python -c 'from utils import row_counter as run; out = run("[1, 2, 3]"); print(out)'
3
$ python -c 'from utils import dataset_hashing as run; out = run("foo"); print(out)'
04e0bb39f30b1a3feb89f536c93be15055482df748674b00d26e5a75777702e9
$ python -c 'from utils import dataset_append as run; out = run("[1, 2, 3]", "[4, 5, 6]"); print(out)'
('[1,2,3,4,5,6]', '3b27ea06e1a721ca6709a283026372e7ff388331242dac94548544b35c2db9b6')
````

[Poetry]: https://python-poetry.org
[this repo]: https://github.com/ntls-io/rust-sgx-sdk-dev-env
