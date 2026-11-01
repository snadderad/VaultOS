# SecureVault OS

SecureVault is an experimental Linux command-line application for opening and browsing a LUKS-encrypted file vault. It is not a complete operating system or a production-ready security product.

## Status and safety

This project has not been security-audited. Do not store valuable or irreplaceable data in it, and do not run it on a machine containing data you cannot afford to lose.

**Important:** After 10 unsuccessful unlock attempts, the program exits without automatically destroying files or powering off the machine. Blank passphrases and mount failures also count toward the limit. The delete and wipe menu actions explicitly run `shred` and can permanently destroy data. Only proceed with disposable data in an isolated Linux virtual machine.


## Requirements

- Linux, or WSL with the required Linux utilities available
- A C++17 compiler such as `g++`
- `cryptsetup`, `mount`, `umount`, and `shred` at runtime
- Root privileges to open and mount the encrypted volume

## Build

From the project directory:

```sh
g++ -O2 -std=c++17 VaultOS.cpp -o securevault
```

The VS Code task **build vault** runs this command.

## Run

The application expects a LUKS volume image named `vault.img` in its current working directory, with a mountable filesystem inside it. It opens the image as the `securevault` mapper and mounts it at `/data`; it does not create or initialize the image or mount point.

Only use a disposable test image in an isolated environment. From the project directory, run:

```sh
sudo ./securevault
```

The VS Code task **run vault** invokes the program through Bash and `sudo`.

The application can list, view, create, and delete regular `.txt` and `.md` files in the verified mounted vault. Names may not start with a dot or contain `/` or `..`, and are limited to 255 characters. Press **L** in the file menu to lock and exit. The **W** action attempts to shred every regular file in the vault; it does not automatically power off the machine.

## Repository contents

- `VaultOS.cpp` — terminal application source
- `.vscode/tasks.json` — VS Code build and run tasks

A local Buildroot checkout is not required to build or run this application and is not included in this repository. Keep any Buildroot version or customizations in a separately managed checkout.

## Limitations

This project is a prototype. Its behavior, scripts, and security properties have not been independently reviewed. Shredding is not guaranteed to securely erase data on SSDs, copy-on-write filesystems, snapshots, or other storage layers. LUKS protects data at rest only while the volume is locked; it does not protect an unlocked, mounted vault from a compromised system.