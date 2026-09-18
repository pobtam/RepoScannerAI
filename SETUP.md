# Setting up

You need two free programs. If you already have them, skip to
[Running it](#running-it).

---

## 1. Install Go

Go is the language the backend is written in.

1. Open **https://go.dev/dl/**
2. Download the installer for your computer:
   * **Mac** — the file ending in `.pkg` (choose `arm64` for an Apple-silicon
     Mac, `amd64` for an Intel one; if unsure, `arm64` is right for any Mac
     bought after 2020)
   * **Windows** — the file ending in `.msi`
   * **Linux** — the `.tar.gz`, and follow the instructions on that page
3. Run the installer and accept the defaults.
4. **Close your terminal window and open a new one.** The installer changes
   your path, and an already-open window will not see it.

To check it worked, type:

```
go version
```

You should see something like `go version go1.24.0 darwin/arm64`.

## 2. Install Node.js

Node.js runs the web interface.

1. Open **https://nodejs.org/en/download**
2. Choose the version marked **LTS** (long-term support).
3. Download the installer for your computer and run it, accepting the defaults.
4. **Close your terminal window and open a new one.**

To check it worked:

```
node --version
```

You should see something like `v22.11.0`. Any version 18 or newer is fine.

---

## 3. Prepare the project

In a terminal, go to the folder containing this file and run:

```
./setup.sh
```

This will:

* check that Go and Node.js are installed, and stop with a clear message if
  either is missing — it will never install system software for you;
* build the backend, and report a compile error now rather than later;
* download the web interface's packages from the public npm registry;
* generate the interface's types from the backend's own schema, so the two
  cannot disagree about the shape of the data.

It prints **Setup complete.** when it has finished. It is safe to run again at
any time; it changes nothing outside this folder.

### If setup fails

* **"Go is NOT installed"** or **"Node.js is NOT installed"** — install the
  missing one above, then open a NEW terminal and run `./setup.sh` again.
* **"permission denied: ./setup.sh"** — run `chmod +x setup.sh run.sh` once,
  then try again.
* **npm errors about the network** — setup needs internet access once, to
  download the interface's packages. After that, nothing does.
* **Anything else** — the error is printed in full. The scripts do not hide
  failures or continue past them.

---

## Running it

```
./run.sh
```

Then open **http://localhost:5173**.

Press **Ctrl-C** in the terminal to stop it. That stops both halves of the app.

### Optional: with a real database

The demonstration keeps everything in memory, which is why it needs no
database. If you want to see it running against PostgreSQL:

```
./run.sh --postgres
```

This needs **Docker** installed (https://www.docker.com/products/docker-desktop/).
It starts a PostgreSQL container, applies the database migrations, and points
the backend at it.

Two honest warnings about that mode:

* It starts **empty**. The demonstration data is only seeded into the in-memory
  mode, because seeding invented findings into a durable database is how
  invented findings end up being quoted as real ones.
* The interface will show an **authentication error**, and that is correct
  behaviour. When the backend serves real data it requires an authenticating
  proxy in front of it, because the browser is never the thing that decides
  who may see a secret finding. That mode exists to exercise the database and
  the migrations, not to browse.
