#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
#
# sdkmanager.py - part of the F-Droid tools
#
# Copyright (C) 2021, Hans-Christoph Steiner <hans@eds.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argcomplete
import argparse
import configparser
import os
import json
import re
import requests
import requests_cache


COMPATIBLE_VERSION = '26.1.1'

CHECKSUMS_URL = (
    'https://gitlab.com/fdroid/android-sdk-transparency-log/-/raw/master/checksums.json'
)

HTTP_HEADERS = {'User-Agent': 'F-Droid'}

CACHEDIR = os.path.join(os.getenv('HOME'), '.cache', os.path.basename(__file__))

BUILD_REGEX = re.compile(r'[1-9][0-9]{6}')
NDK_RELEASE_REGEX = re.compile(r'r[1-9][0-9]?[a-z]?')

USAGE = """
Usage: 
  sdkmanager [--uninstall] [<common args>] [--package_file=<file>] [<packages>...]
  sdkmanager --update [<common args>]
  sdkmanager --list [<common args>]
  sdkmanager --licenses [<common args>]
  sdkmanager --version

With --install (optional), installs or updates packages.
    By default, the listed packages are installed or (if already installed)
    updated to the latest version.
With --uninstall, uninstall the listed packages.

    <package> is a sdk-style path (e.g. "build-tools;23.0.0" or
             "platforms;android-23").
    <package-file> is a text file where each line is a sdk-style path
                   of a package to install or uninstall.
    Multiple --package_file arguments may be specified in combination
    with explicit paths.

With --update, all installed packages are updated to the latest version.

With --list, all installed and available packages are printed out.

With --licenses, show and offer the option to accept licenses for all
     available packages that have not already been accepted.

With --version, prints the current version of sdkmanager.

Common Arguments:
    --sdk_root=<sdkRootPath>: Use the specified SDK root instead of the SDK 
                              containing this tool

    --channel=<channelId>: Include packages in channels up to <channelId>.
                           Common channels are:
                           0 (Stable), 1 (Beta), 2 (Dev), and 3 (Canary).

    --include_obsolete: With --list, show obsolete packages in the
                        package listing. With --update, update obsolete
                        packages as well as non-obsolete.

    --no_https: Force all connections to use http rather than https.

    --proxy=<http | socks>: Connect via a proxy of the given type.

    --proxy_host=<IP or DNS address>: IP or DNS address of the proxy to use.

    --proxy_port=<port #>: Proxy port to connect to.

    --verbose: Enable verbose output.

* If the env var REPO_OS_OVERRIDE is set to "windows",
  "macosx", or "linux", packages will be downloaded for that OS.
"""

packages = dict()


def download_file(url, local_filename=None, dldir='tmp'):
    filename = url.split('/')[-1]
    if local_filename is None:
        local_filename = os.path.join(dldir, filename)
    # the stream=True parameter keeps memory usage low
    r = requests.get(url, stream=True, allow_redirects=True, headers=HEADERS)
    r.raise_for_status()
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return local_filename


def get_properties_dict(k, d):
    config = configparser.ConfigParser()
    config.read_string('[DEFAULT]\n' + d[k])
    return dict(config.items('DEFAULT'))


def parse_ndk(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict('source.properties', d)
        revision = source_properties['pkg.revision']
        for k in ('ndk', 'ndk-bundle'):
            key = (k, revision)
            if key not in packages:
                packages[key] = url
    m = NDK_RELEASE_REGEX.search(url)
    if m:
        release = m.group()
        packages[('ndk', release)] = url
        packages[('ndk-bundle', release)] = url


def parse_build_tools(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict('source.properties', d)
        revision = source_properties['pkg.revision'].replace(' ', '-')
        key = ('build-tools', revision)
        if key not in packages:
            packages[key] = url


# TODO allow : and - as separator, e.g. ndk-22.1.7171670
# verify GPG signature
# only use android-sdk-transparency-log as source
def build_package_list(use_net=False):
    cached_checksums = os.path.join(CACHEDIR, os.path.basename(CHECKSUMS_URL))
    if os.path.exists(cached_checksums):
        with open(cached_checksums) as fp:
            checksums = json.load(fp)
    requests_cache.install_cache(CACHEDIR)
    r = requests.get(CHECKSUMS_URL)
    r.raise_for_status()
    checksums = r.json()

    for url in checksums.keys():
        if not url.endswith('.zip'):
            continue

        if os.path.basename(url).startswith('build-tools'):
            parse_build_tools(url, checksums[url][-1])
        elif 'ndk-' in url:
            # print(os.path.basename(k), checksums[k])
            parse_ndk(url, checksums[url][0])

    import pprint

    pprint.pprint(packages)


def list():
    global packages
    print(type(packages))
    path_width = 0
    names = []
    for package in packages:
        name = ';'.join(package)
        if len(name) > path_width:
            path_width = len(name)
        names.append(name)
    print('Installed Packages:')
    print('  ' + 'Path'.ljust(path_width) + ' | Version       | Description | Location')
    print(
        '  ' + '-------'.ljust(path_width) + ' | -------       | -------     | -------'
    )
    print()
    print('Available Packages:')
    print('  ' + 'Path'.ljust(path_width) + ' | Version       | Description')
    print('  ' + '-------'.ljust(path_width) + ' | -------       | -------')
    for name in sorted(names):
        print('  %s |               | ' % name.ljust(path_width))


def main():
    build_package_list()
    # TODO  then feed as argument options
    parser = argparse.ArgumentParser()
    # commands
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--licenses", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--version", action="store_true")

    # "common arguments"
    parser.add_argument("--channel")
    parser.add_argument("--include_obsolete")
    parser.add_argument("--no_https")
    parser.add_argument("--proxy")
    parser.add_argument("--proxy_host")
    parser.add_argument("--proxy_port")
    parser.add_argument("--sdk_root")
    parser.add_argument(
        "--verbose", action="store_true", help="increase output verbosity"
    )
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    command = None
    for k in ('install', 'licenses', 'list', 'uninstall', 'update', 'version'):
        if args.__dict__[k]:
            if command is not None:
                print(
                    'Error: Only one of --uninstall, --install, --licenses, '
                    '--update, --list, --version can be specified.'
                )
                print(USAGE)
                exit(1)
            command = k
    if command is None:
        command = 'install'

    method = globals().get(command)
    if not method:
        raise NotImplementedError("Command %s not implemented" % command)
    method()


if __name__ == "__main__":
    main()
