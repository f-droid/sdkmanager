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

import argparse
import configparser
import io
import os
import json
import re
import requests
import shutil
import stat
import tempfile
import textwrap
import zipfile
from distutils.version import LooseVersion
from pathlib import Path
from urllib.parse import urlparse


COMPATIBLE_VERSION = '26.1.1'

CHECKSUMS_URL = (
    'https://gitlab.com/fdroid/android-sdk-transparency-log/-/raw/master/checksums.json'
)

HTTP_HEADERS = {'User-Agent': 'F-Droid'}

CACHEDIR = Path.home() / '.cache/sdkmanager'
CACHED_CHECKSUMS = CACHEDIR / os.path.basename(CHECKSUMS_URL)
ANDROID_SDK_ROOT = os.getenv(
    'ANDROID_SDK_ROOT', os.getenv('ANDROID_HOME', '/opt/android-sdk')
)

BUILD_REGEX = re.compile(r'[1-9][0-9]{6}')
NDK_RELEASE_REGEX = re.compile(r'r[1-9][0-9]?[a-z]?')
M2REPOSITORY_REVISION_REGEX = re.compile(r'android_m2repository_r([0-9]+)\.zip')

# The sub-directory to install a given package into, assumes ANDROID_SDK_ROOT as root
INSTALL_DIRS = {
    'build-tools': 'build-tools/{revision}',
    'cmake': 'cmake/{revision}',
    'emulator': 'emulator',
    'ndk': 'ndk/{revision}',
    'ndk-bundle': 'ndk-bundle',
    'platforms': 'platforms/{revision}',
    'platform-tools': 'platform-tools',
    'tools': 'tools',
    'extras;android;m2repository': 'extras/android/m2repository',
}

PACKAGE_XML_TEMPLATE = textwrap.dedent(
    """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <ns2:repository
        xmlns:ns2="http://schemas.android.com/repository/android/common/01"
        xmlns:ns3="http://schemas.android.com/repository/android/generic/01"
        xmlns:ns4="http://schemas.android.com/sdk/android/repo/addon2/01"
        xmlns:ns5="http://schemas.android.com/sdk/android/repo/repository2/01"
        xmlns:ns6="http://schemas.android.com/sdk/android/repo/sys-img2/01">
      <localPackage path="{path}">
        <type-details xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ns3:genericDetailsType"/>
        <revision>{revision}</revision>
        <display-name>PLACEHOLDER</display-name>
        <uses-license ref="android-sdk-license"/>
      </localPackage>
    </ns2:repository>
"""
).strip()

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
revisions = dict()


def download_file(url, local_filename=None, dldir=CACHEDIR):
    filename = os.path.basename(urlparse(url).path)
    if local_filename is None:
        local_filename = dldir / filename
    print('Downloading', url, 'into', local_filename)
    # the stream=True parameter keeps memory usage low
    r = requests.get(url, stream=True, allow_redirects=True, headers=HTTP_HEADERS)
    r.raise_for_status()
    with local_filename.open('wb') as f:
        for chunk in r.iter_content(chunk_size=io.DEFAULT_BUFFER_SIZE):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return local_filename


def get_properties_dict(string):
    config = configparser.ConfigParser(delimiters=('='))
    config.read_string('[DEFAULT]\n' + string)
    return dict(config.items('DEFAULT'))


def _add_to_revisions(url, source_properties):
    pkg_revision = source_properties.get('pkg.revision')
    if pkg_revision:
        revisions[url] = tuple(LooseVersion(pkg_revision).version)


def parse_build_tools(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        revision = source_properties['pkg.revision'].replace(' ', '-')
        key = ('build-tools', revision)
        if key not in packages:
            packages[key] = url


def parse_cmake(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        key = tuple(source_properties['pkg.path'].split(';'))
        if key not in packages:
            packages[key] = url


def parse_emulator(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        key = tuple(source_properties['pkg.path'].split(';'))
        if key not in packages:
            packages[key] = url
        versioned = (key[0], source_properties['pkg.revision'])
        if versioned not in packages:
            packages[versioned] = url


def parse_m2repository(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        # source.properties does not reliably contain Pkg.Revision or the path info
        m = M2REPOSITORY_REVISION_REGEX.search(url)
        if m:
            revision = m.group(1)
            key = ('extras', 'android', 'm2repository')
            packages[key] = url
            versioned = key + tuple([revision])
            if versioned not in packages:
                packages[versioned] = url
            noleading0 = key + tuple([revision.lstrip('0')])
            if noleading0 not in packages:
                packages[noleading0] = url


def parse_ndk(url, d):
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
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


def parse_platforms(url, d):
    """Parse platforms and choose the URL with the highest release number

    These packages are installed by API version,
    e.g. platforms;android-29, but there are multiple releases
    available, e.g. platform-29_r05.zip, platform-29_r04.zip, etc.

    """
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        apilevel = source_properties['androidversion.apilevel']
        # TODO this should make all versions/revisions available, not only most recent
        key = ('platforms', 'android-%s' % apilevel)
        if key in packages:
            packages[key] = sorted([url, packages.get(key)])[-1]
        else:
            packages[key] = url


def parse_platform_tools(url, d):
    """Find all platform-tools packages and set highest version as 'platform-tools'"""
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        key = ('platform-tools', source_properties.get('pkg.revision'))
        if key not in packages:
            packages[key] = url

    highest = '0'
    for key, url in packages.items():
        if key[0] != 'platform-tools' or len(key) < 2:
            continue
        version = key[-1]
        if LooseVersion(version) > LooseVersion(highest):
            highest = version
    packages[('platform-tools',)] = packages[('platform-tools', highest)]


def parse_tools(url, d):
    """Find all tools packages and set highest version as 'tools'"""
    if 'source.properties' in d:
        source_properties = get_properties_dict(d['source.properties'])
        _add_to_revisions(url, source_properties)
        path = source_properties.get('pkg.path')
        if not path:
            path = 'tools'
        key = (path, source_properties.get('pkg.revision'))
        if key not in packages:
            packages[key] = url

    highest = '0'
    for key, url in packages.items():
        if key[0] != 'tools' or len(key) < 2:
            continue
        version = key[-1]
        if LooseVersion(version) > LooseVersion(highest):
            highest = version
    packages[('tools',)] = packages[('tools', highest)]


def parse_repositories_cfg(f):
    """parse the supplied repositories.cfg and return a list of URLs"""
    with Path(f).open() as fp:
        data = get_properties_dict(fp.read())

    disabled = set()
    for k, v in data.items():
        if k.startswith('@disabled@'):
            if v == 'disabled':
                url = k.split('@')[2]
                disabled.add(url)

    count = int(data.get('count', '0'))
    i = 0
    repositories = []
    while i < count:
        d = dict()
        for k in ('disp', 'dist', 'enabled', 'src'):
            key_i = '%s%02d' % (k, i)
            if data.get(key_i):
                d[k] = data[key_i]
        if d[k] not in disabled:
            repositories.append(d)
        i += 1
    enabled_repositories = []
    for d in repositories:
        v = d.get('enabled', 'true')
        if v == 'true':
            url = d.get('src', '').replace('\\', '')
            if url and url not in enabled_repositories:
                enabled_repositories.append(url)
    return enabled_repositories


# TODO allow : and - as separator, e.g. ndk-22.1.7171670
# verify GPG signature
# only use android-sdk-transparency-log as source
def build_package_list(use_net=False):
    if CACHED_CHECKSUMS.exists():
        with CACHED_CHECKSUMS.open() as fp:
            _process_checksums(json.load(fp))
    else:
        use_net = True  # need to fetch checksums.json, no cached version

    etag_file = CACHED_CHECKSUMS.parent / (CACHED_CHECKSUMS.name + '.etag')
    if etag_file.exists():
        etag = etag_file.read_text()
        HTTP_HEADERS['If-None-Match'] = etag
    else:
        etag = None

    if use_net:
        try:
            r = requests.get(CHECKSUMS_URL, allow_redirects=True, headers=HTTP_HEADERS)
        except ValueError as e:
            if etag_file.exists():
                etag_file.unlink()
            print('ERROR:', e)
            exit(1)
        r.raise_for_status()

        if etag is None or etag != r.headers.get('etag'):
            CACHED_CHECKSUMS.write_bytes(r.content)
            etag_file.write_text(r.headers['etag'])
            _process_checksums(r.json())


def _process_checksums(checksums):
    for url in checksums.keys():
        if not url.endswith('.zip'):
            continue

        basename = os.path.basename(url)
        if basename.startswith('build-tools'):
            for entry in checksums[url]:
                parse_build_tools(url, entry)
        elif basename.startswith('cmake'):
            for entry in checksums[url]:
                parse_cmake(url, entry)
        elif basename.startswith('emulator'):
            for entry in checksums[url]:
                parse_emulator(url, entry)
        elif basename.startswith('android_m2repository_r'):
            for entry in checksums[url]:
                parse_m2repository(url, entry)
        elif 'ndk-' in url:
            parse_ndk(url, checksums[url][0])
        elif basename.startswith('platform-tools'):
            for entry in checksums[url]:
                parse_platform_tools(url, entry)
        elif basename.startswith('android-') or basename.startswith('platform-'):
            for entry in checksums[url]:
                parse_platforms(url, entry)
        elif basename.startswith('tools') or basename.startswith('sdk-tools-'):
            for entry in checksums[url]:
                parse_tools(url, entry)


def licenses():
    """prompt the user to accept the various licenses

    TODO actually implement it, this largely fakes it.

    https://cs.android.com/android-studio/platform/tools/base/+/mirror-goog-studio-main:sdklib/src/main/java/com/android/sdklib/tool/sdkmanager/LicensesAction.java
    https://cs.android.com/android-studio/platform/tools/base/+/mirror-goog-studio-main:repository/src/main/java/com/android/repository/api/License.java

    """
    global ANDROID_SDK_ROOT
    known_licenses = {
        'android-sdk-license': '\n8933bad161af4178b1185d1a37fbf41ea5269c55\n\nd56f5187479451eabf01fb78af6dfcb131a6481e\n24333f8a63b6825ea9c5514f83c2829b004d1fee',
        'android-sdk-preview-license': '\n84831b9409646a918e30573bab4c9c91346d8abd\n',
        'android-sdk-preview-license-old': '79120722343a6f314e0719f863036c702b0e6b2a\n\n84831b9409646a918e30573bab4c9c91346d8abd',
        'intel-android-extra-license': '\nd975f751698a77b662f1254ddbeed3901e976f5a\n',
    }
    known_license_hashes = set()
    for license_value in known_licenses.values():
        for license in license_value.strip().split('\n'):
            if license:
                known_license_hashes.add(license)

    found_license_hashes = set()
    licenses_dir = Path(ANDROID_SDK_ROOT) / 'licenses'
    for f in licenses_dir.glob('*'):
        with f.open() as fp:
            for license in fp.read().strip().split('\n'):
                if license:
                    found_license_hashes.add(license)

    total = len(known_license_hashes)
    license_count = total - len(found_license_hashes)
    if license_count == 0:
        print('All SDK package licenses accepted.')
        return
    elif license_count == 1:
        fl = ('1', '1', '', 's')
    else:
        fl = (license_count, total, 's', 've')
    msg = (
        "{0} of {1} SDK package license{2} not accepted.\n"
        "Review license{2} that ha{3} not been accepted (y/N)? "
    ).format(*fl)
    s = input(msg)
    print()
    if s.lower() in ('y', 'yes'):
        licenses_dir.mkdir(exist_ok=True)
        for h in known_license_hashes:
            if h not in found_license_hashes:
                for license_file, known in known_licenses.items():
                    if h in known:
                        with (licenses_dir / license_file).open('w') as fp:
                            fp.write(known)


def install(to_install):
    """Install specified packages, including downloading them as needed

    Certain packages are installed into versioned sub-directories
    while a couple of other are always installed into the same
    location.  In those other cases, if that location exists, the
    directory will be removed before installing the package.  These
    installed packages will always contain at least
    'source.properties'.

    Parameters
    ----------

    to_install
        A single package or list of packages to install.

    """
    global packages

    if isinstance(to_install, str):
        to_install = [to_install]
    for package in to_install:
        key = tuple(package.split(';'))
        url = packages[key]
        zipball = CACHEDIR / os.path.basename(url)
        if not zipball.exists():
            download_file(url, zipball)

        if key[0] == 'extras' and len(key) in (3, 4):
            name = ';'.join(key[:3])
        else:
            name = key[0]

        package_sub_dir = INSTALL_DIRS[name]
        if len(key) > 1:
            install_dir = ANDROID_SDK_ROOT / package_sub_dir.format(revision=key[-1])
        else:
            install_dir = ANDROID_SDK_ROOT / package_sub_dir
        if '/' not in package_sub_dir and (install_dir / 'source.properties').exists():
            shutil.rmtree(install_dir)
        install_dir.parent.mkdir(parents=True, exist_ok=True)
        _install_zipball_from_cache(zipball, install_dir)
        _generate_package_xml(install_dir, package, url)


def _install_zipball_from_cache(zipball, install_dir):
    unzip_dir = Path(tempfile.mkdtemp(prefix='.sdkmanager-'))

    print('Unzipping to %s' % unzip_dir)
    toplevels = set()
    try:
        with zipfile.ZipFile(str(zipball)) as zipfp:
            for info in zipfp.infolist():
                permbits = info.external_attr >> 16
                writefile = str(unzip_dir / info.filename)
                if stat.S_ISLNK(permbits):
                    link = unzip_dir / info.filename
                    link.parent.mkdir(0o755, parents=True, exist_ok=True)
                    link_target = zipfp.read(info).decode()
                    os.symlink(link_target, str(link))

                    try:
                        link.resolve().relative_to(unzip_dir)
                    except (FileNotFoundError, ValueError):
                        link.unlink()
                        trim_at = len(str(unzip_dir)) + 1
                        print(
                            'ERROR: Unexpected symlink target: {link} -> {target}'.format(
                                link=str(link)[trim_at:], target=link_target
                            )
                        )
                elif stat.S_ISDIR(permbits) or stat.S_IXUSR & permbits:
                    zipfp.extract(info.filename, path=str(unzip_dir))
                    os.chmod(writefile, 0o755)  # nosec bandit B103
                else:
                    zipfp.extract(info.filename, path=str(unzip_dir))
                    os.chmod(writefile, 0o644)  # nosec bandit B103
            toplevels.update([p.split('/')[0] for p in zipfp.namelist()])
    except zipfile.BadZipFile as e:
        print('ERROR:', e)
        if zipball.exists():
            zipball.unlink()
        return

    print('Installing into', install_dir)
    if len(toplevels) == 1:
        for extracted in unzip_dir.glob('*'):
            shutil.move(str(extracted), str(install_dir))
    else:
        install_dir.mkdir(parents=True)
        for extracted in unzip_dir.glob('*'):
            shutil.move(str(extracted), str(install_dir))
    if zipball.exists():
        zipball.unlink()


def _generate_package_xml(install_dir, package, url):
    """Generate package.xml for an installed package"""
    revision = revisions[url]
    template = ('<major>{0}</major>', '<minor>{1}</minor>', '<micro>{2}</micro>')
    r = min(3, len(revision))
    d = {'revision': ''.join(template[:r]).format(*revision), 'path': package}
    with (install_dir / 'package.xml').open('w') as fp:
        fp.write(PACKAGE_XML_TEMPLATE.format(**d))


def list():
    global packages

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
    global CACHEDIR, ANDROID_SDK_ROOT, ANDROID_NDK_ROOT

    if ANDROID_SDK_ROOT:
        ANDROID_SDK_ROOT = Path(ANDROID_SDK_ROOT)
    if not ANDROID_SDK_ROOT.parent.exists():
        print(__file__, 'writes into $ANDROID_SDK_ROOT but it does not exist!')
        exit(1)
    ANDROID_SDK_ROOT.mkdir(exist_ok=True)

    CACHEDIR.mkdir(mode=0o0700, parents=True, exist_ok=True)

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

    parser.add_argument('packages', nargs='*')

    # do not require argcomplete to keep the install profile light
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

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
    elif command == 'version':
        print('25.2.0')
        exit()

    method = globals().get(command)
    if not method:
        raise NotImplementedError('Command "--%s" not implemented' % command)
    if command in ('install', 'uninstall'):
        build_package_list(use_net=False)
        method(args.packages)
    else:
        build_package_list(use_net=True)
        method()


if __name__ == "__main__":
    main()
