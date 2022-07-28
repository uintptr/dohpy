#!/usr/bin/env python3

import sys
import os
import shutil
import argparse
import pwd
import subprocess
from typing import Tuple

DEFAULT_ROOT = "/opt/dohpy"
SCRIPT_NAME = "doh.py"
SYSTEMD_SERVICE_NAME = "dohpy"


class ConfigurationError(Exception):
    pass


def printkv(n, v) -> None:
    name = f"{n}:"
    print(f"    {name:<20} {v}")


def shell_exec(cmd, check=True) -> None:

    subprocess.run(cmd, shell=True, check=check, capture_output=True)


def is_systemd() -> bool:
    # find a safer way to do this
    return os.path.isdir("/etc/systemd")


def install_systemd(install_root: str, config: str) -> None:

    config_file_name = f"{SYSTEMD_SERVICE_NAME}.service"

    config_file = os.path.join(install_root, config_file_name)

    link_file = os.path.join("/etc/systemd/system", config_file_name)

    with open(config_file, "w+") as f:
        f.write(config)

    if(True == os.path.isfile(link_file)):
        os.unlink(link_file)

    os.symlink(config_file, link_file)

    shell_exec("systemctl daemon-reload")
    shell_exec(f"systemctl enable {SYSTEMD_SERVICE_NAME}.service")
    shell_exec(f"systemctl start  {SYSTEMD_SERVICE_NAME}.service")


def build_systemd_file(install_root: str, script: str) -> str:

    config = """
[Unit]
Description=Dns Over HTTPS (doh.py) Service

[Service]
ExecStart=__PYTHON3__ __SCRIPT__
WorkingDirectory=__INSTALL_ROOT__
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""

    config = config.replace("__PYTHON3__", sys.executable)
    config = config.replace("__SCRIPT__", script)
    config = config.replace("__INSTALL_ROOT__", install_root)

    return config


def get_user_id(name: str) -> Tuple[int, int]:

    try:
        entry = pwd.getpwnam(name)
        return (entry.pw_uid, entry.pw_gid)
    except KeyError:
        raise ConfigurationError(f'User "{name}" not found')


"""
systemctl stop [servicename]
systemctl disable [servicename]
rm /etc/systemd/system/[servicename]
rm /etc/systemd/system/[servicename] # and symlinks that might be related
rm /usr/lib/systemd/system/[servicename]
rm /usr/lib/systemd/system/[servicename] # and symlinks that might be related
systemctl daemon-reload
systemctl reset-failed
"""


def uninstall(install_root: str) -> None:

    service_name = f"{SYSTEMD_SERVICE_NAME}.service"

    # best effort
    shell_exec(f"systemctl stop {service_name}", check=False)
    shell_exec(f"systemctl disable {service_name}", check=False)

    service_file_1 = os.path.join("/etc/systemd/system", service_name)
    service_file_2 = os.path.join("/usr/lib/systemd/system", service_name)

    if(True == os.path.isfile(service_file_1)):
        os.unlink(service_file_1)

    if(True == os.path.isfile(service_file_2)):
        os.unlink(service_file_2)

    shell_exec("systemctl daemon-reload", check=False)
    shell_exec("systemctl reset-failed", check=False)

    if(True == os.path.isdir(install_root)):
        shutil.rmtree(install_root)


def install(install_root: str) -> None:

    script = os.path.dirname(sys.argv[0])
    script = os.path.join(script, "..", SCRIPT_NAME)
    script = os.path.abspath(script)

    printkv("Install Directory", install_root)
    printkv("Server", script)

    # Make sure the user exists and get its user/group id
    (uid, gid) = get_user_id("nobody")

    # Add the directory if it doesn't exist already
    if(False == os.path.isdir(install_root)):
        os.makedirs(install_root)

    # Make sure it's owned by the user
    os.chown(install_root, uid, gid)

    # Copy the server script ( doh.py ) and change its owner
    out_script = os.path.join(install_root, SCRIPT_NAME)
    shutil.copy2(script, out_script)

    os.chown(out_script, uid, gid)

    # Build the systemd script file
    service_config = build_systemd_file(install_root, out_script)

    # Install systemd config file
    install_systemd(install_root, service_config)


def upgrade(install_root: str) -> None:

    script = os.path.dirname(sys.argv[0])
    script = os.path.join(script, "..", SCRIPT_NAME)
    script = os.path.abspath(script)

    printkv("Install Directory", install_root)

    # Copy the server script ( doh.py ) and change its owner
    out_script = os.path.join(install_root, SCRIPT_NAME)
    shutil.copy2(script, out_script)

    shell_exec(f"systemctl restart {SYSTEMD_SERVICE_NAME}.service")


def main() -> int:
    status = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("-i",
                        "--install-root",
                        default=DEFAULT_ROOT,
                        required=False,
                        type=str,
                        help=f"Install Directory. Default: {DEFAULT_ROOT}")

    parser.add_argument("--install",
                        action="store_true",
                        help="Install the service")

    parser.add_argument("--uninstall",
                        action="store_true",
                        help="Uninstall the service")

    parser.add_argument("--upgrade",
                        action="store_true",
                        help="Upgrade the service")

    args = parser.parse_args()

    # normalize
    install_root = os.path.abspath(args.install_root)

    try:
        # Make sure we're running as r00t
        if(0 != os.getuid()):
            raise PermissionError("Must be running as root")

        # Only supporting systemd at this time
        if(False == is_systemd()):
            raise ConfigurationError("systemd not supported")

        if(True == args.install):
            install(install_root)
        elif(True == args.uninstall):
            uninstall(install_root)
        elif(True == args.upgrade):
            upgrade(install_root)
        else:
            raise NotImplementedError("Missing argument")
        status = 0
    except PermissionError as e:
        print("Error:", e)
    except ConfigurationError as e:
        print("Error:", e)
    except subprocess.CalledProcessError as e:
        print("Error:", e)
    except NotImplementedError as e:
        print("Error", e)
    finally:
        if(False == args.uninstall and 0 != status and 0 == os.getuid()):
                uninstall(install_root)

    return status


if __name__ == '__main__':
    status = main()

    if(0 != status):
        sys.exit(status)
