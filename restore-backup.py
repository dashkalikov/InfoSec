"""Restore the encrypted 3FA workspace backup into a fresh installation."""

import argparse
import base64
import configparser
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

HEADER = b"3FA-BACKUP\x01"
PREFERENCES = "preferences.json"
DATABASES = ("3FA/databases/3fa_users.db", "3FA/databases/ca.db")
CONFIGS = ("3FA/config/email.json", "3FA/config/ca.json")
APP_DIRS = ("rsa_keys", "generated_primes", "encrypted_files", "decrypted_files", "exports")
DATA_DIRS = (
    *(f"3FA/{name}/" for name in APP_DIRS),
    *(f"WinNTL-11_6_0/{name}/" for name in APP_DIRS),
    "encrypted_files/", "decrypted_files/", "rsa_keys/",
    "3FA/ca/private/", "3FA/ca/certs/", "3FA/ca/certificates/", "3FA/ca/issued/", "3FA/ca/crl/",
)
DOCKER_DIRS = {
    **{f"3FA/{name}": f"/opt/threefa/{name}" for name in ("databases", "config", "rsa_keys", "generated_primes")},
    "3FA/exports": "/home/threefa/exports",
}


def valid_path(name):
    path = PurePosixPath(name)
    return (
        path.as_posix() == name and not path.is_absolute() and ".." not in path.parts
        and "\\" not in name and ":" not in name
        and (name in DATABASES or name in CONFIGS or name.startswith(DATA_DIRS))
    )


def decrypt_backup(archive, key_file):
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ValueError("Install cryptography in this Python environment.") from None

    key = base64.b64decode(key_file.read_bytes().strip(), validate=True)
    payload = archive.read_bytes()
    if len(key) != 32 or not payload.startswith(HEADER) or len(payload) < len(HEADER) + 28:
        raise ValueError("Invalid backup or key file format.")
    start = len(HEADER)
    try:
        return AESGCM(key).decrypt(payload[start:start + 12], payload[start + 12:], HEADER)
    except InvalidTag:
        raise ValueError("Backup authentication failed. Check the key and archive.") from None


def write_preferences(values):
    theme = values.get("theme")
    zoom = values.get("zoom")
    appearance = {}
    if theme in ("light", "dark"):
        appearance["theme"] = theme
    if type(zoom) is int and 75 <= zoom <= 200:
        appearance["zoom"] = zoom
    if not appearance:
        return

    if os.name == "nt":
        import winreg

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\3FA Security\3FA\appearance") as key:
            for name, value in appearance.items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, kind, value)
        return

    config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    path = config_home / "3FA Security" / "3FA.conf"
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read(path, encoding="utf-8")
    if not config.has_section("appearance"):
        config.add_section("appearance")
    for name, value in appearance.items():
        config["appearance"][name] = str(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as settings:
        config.write(settings, space_around_delimiters=False)


def restore_files(payload, root=None, *, preferences=True):
    """With no project root, restore to the mounted volumes inside the container."""
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or DATABASES[0] not in names:
            raise ValueError("Backup file list is incomplete or contains duplicates.")
        appearance = json.loads(archive.read(PREFERENCES)) if PREFERENCES in names else {}
        if not isinstance(appearance, dict):
            raise ValueError("Invalid appearance settings.")

        targets = []
        for name in names:
            if name == PREFERENCES:
                continue
            if not valid_path(name):
                raise ValueError("Backup contains an unexpected path.")
            if root is not None:
                base, relative = root, name
            else:
                mount = next((key for key in DOCKER_DIRS if name.startswith(key + "/")), None)
                if mount is None:
                    continue
                base, relative = Path(DOCKER_DIRS[mount]), name[len(mount) + 1:]
            target = base / relative
            if not target.resolve().is_relative_to(base.resolve()) or target.is_symlink():
                raise ValueError("Restore path points outside its data directory.")
            if target.exists():
                raise ValueError(f"Restore stopped because {name} already exists. Use a fresh installation.")
            targets.append((name, target))

        created = []
        try:
            for name, target in targets:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created.append(target)
                with os.fdopen(fd, "wb") as output:
                    output.write(archive.read(name))
            if preferences:
                write_preferences(appearance)
        except BaseException:
            for target in reversed(created):
                target.unlink(missing_ok=True)
            raise
    return len(targets)


def restore_docker(payload, root):
    compose = ["docker", "compose"]
    running = subprocess.run(compose + ["ps", "-q", "--status", "running", "app"],
                             cwd=root, capture_output=True, check=True)
    if running.stdout.strip():
        raise ValueError("Stop 3FA before restoring with Docker.")
    script = Path(__file__).read_text(encoding="utf-8")
    subprocess.run(
        compose + ["run", "--rm", "--no-deps", "-T", "--build", "--entrypoint",
                   "python3", "app", "-c", script, "--restore-container"],
        cwd=root, input=payload, check=True,
    )


def main():
    if sys.argv[1:] == ["--restore-container"]:
        count = restore_files(sys.stdin.buffer.read())
        print(f"Restored {count} files to Docker volumes.")
        return

    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--archive", type=Path, default=root / "backups" / "workspace.3fa")
    parser.add_argument("--docker", action="store_true", help="restore to Docker volumes")
    args = parser.parse_args()
    payload = decrypt_backup(args.archive, args.key_file)
    if args.docker:
        restore_docker(payload, root)
    else:
        count = restore_files(payload, root)
        print(f"Restored {count} files to the project.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
