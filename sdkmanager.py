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
      <license id="{license_id}" type="text">{license}</license>
      <localPackage path="{path}">
        <type-details xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ns3:genericDetailsType"/>
        <revision>{revision}</revision>
        <display-name>PLACEHOLDER</display-name>
        <uses-license ref="{license_id}"/>
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

ANDROID_SDK_LICENSE = """Terms and Conditions

This is the Android Software Development Kit License Agreement

1. Introduction

1.1 The Android Software Development Kit (referred to in the License Agreement as the "SDK" and specifically including the Android system files, packaged APIs, and Google APIs add-ons) is licensed to you subject to the terms of the License Agreement. The License Agreement forms a legally binding contract between you and Google in relation to your use of the SDK.

1.2 "Android" means the Android software stack for devices, as made available under the Android Open Source Project, which is located at the following URL: http://source.android.com/, as updated from time to time.

1.3 A "compatible implementation" means any Android device that (i) complies with the Android Compatibility Definition document, which can be found at the Android compatibility website (http://source.android.com/compatibility) and which may be updated from time to time; and (ii) successfully passes the Android Compatibility Test Suite (CTS).

1.4 "Google" means Google Inc., a Delaware corporation with principal place of business at 1600 Amphitheatre Parkway, Mountain View, CA 94043, United States.


2. Accepting the License Agreement

2.1 In order to use the SDK, you must first agree to the License Agreement. You may not use the SDK if you do not accept the License Agreement.

2.2 By clicking to accept, you hereby agree to the terms of the License Agreement.

2.3 You may not use the SDK and may not accept the License Agreement if you are a person barred from receiving the SDK under the laws of the United States or other countries, including the country in which you are resident or from which you use the SDK.

2.4 If you are agreeing to be bound by the License Agreement on behalf of your employer or other entity, you represent and warrant that you have full legal authority to bind your employer or such entity to the License Agreement. If you do not have the requisite authority, you may not accept the License Agreement or use the SDK on behalf of your employer or other entity.


3. SDK License from Google

3.1 Subject to the terms of the License Agreement, Google grants you a limited, worldwide, royalty-free, non-assignable, non-exclusive, and non-sublicensable license to use the SDK solely to develop applications for compatible implementations of Android.

3.2 You may not use this SDK to develop applications for other platforms (including non-compatible implementations of Android) or to develop another SDK. You are of course free to develop applications for other platforms, including non-compatible implementations of Android, provided that this SDK is not used for that purpose.

3.3 You agree that Google or third parties own all legal right, title and interest in and to the SDK, including any Intellectual Property Rights that subsist in the SDK. "Intellectual Property Rights" means any and all rights under patent law, copyright law, trade secret law, trademark law, and any and all other proprietary rights. Google reserves all rights not expressly granted to you.

3.4 You may not use the SDK for any purpose not expressly permitted by the License Agreement. Except to the extent required by applicable third party licenses, you may not copy (except for backup purposes), modify, adapt, redistribute, decompile, reverse engineer, disassemble, or create derivative works of the SDK or any part of the SDK.

3.5 Use, reproduction and distribution of components of the SDK licensed under an open source software license are governed solely by the terms of that open source software license and not the License Agreement.

3.6 You agree that the form and nature of the SDK that Google provides may change without prior notice to you and that future versions of the SDK may be incompatible with applications developed on previous versions of the SDK. You agree that Google may stop (permanently or temporarily) providing the SDK (or any features within the SDK) to you or to users generally at Google's sole discretion, without prior notice to you.

3.7 Nothing in the License Agreement gives you a right to use any of Google's trade names, trademarks, service marks, logos, domain names, or other distinctive brand features.

3.8 You agree that you will not remove, obscure, or alter any proprietary rights notices (including copyright and trademark notices) that may be affixed to or contained within the SDK.


4. Use of the SDK by You

4.1 Google agrees that it obtains no right, title or interest from you (or your licensors) under the License Agreement in or to any software applications that you develop using the SDK, including any intellectual property rights that subsist in those applications.

4.2 You agree to use the SDK and write applications only for purposes that are permitted by (a) the License Agreement and (b) any applicable law, regulation or generally accepted practices or guidelines in the relevant jurisdictions (including any laws regarding the export of data or software to and from the United States or other relevant countries).

4.3 You agree that if you use the SDK to develop applications for general public users, you will protect the privacy and legal rights of those users. If the users provide you with user names, passwords, or other login information or personal information, you must make the users aware that the information will be available to your application, and you must provide legally adequate privacy notice and protection for those users. If your application stores personal or sensitive information provided by users, it must do so securely. If the user provides your application with Google Account information, your application may only use that information to access the user's Google Account when, and for the limited purposes for which, the user has given you permission to do so.

4.4 You agree that you will not engage in any activity with the SDK, including the development or distribution of an application, that interferes with, disrupts, damages, or accesses in an unauthorized manner the servers, networks, or other properties or services of any third party including, but not limited to, Google or any mobile communications carrier.

4.5 You agree that you are solely responsible for (and that Google has no responsibility to you or to any third party for) any data, content, or resources that you create, transmit or display through Android and/or applications for Android, and for the consequences of your actions (including any loss or damage which Google may suffer) by doing so.

4.6 You agree that you are solely responsible for (and that Google has no responsibility to you or to any third party for) any breach of your obligations under the License Agreement, any applicable third party contract or Terms of Service, or any applicable law or regulation, and for the consequences (including any loss or damage which Google or any third party may suffer) of any such breach.

5. Your Developer Credentials

5.1 You agree that you are responsible for maintaining the confidentiality of any developer credentials that may be issued to you by Google or which you may choose yourself and that you will be solely responsible for all applications that are developed under your developer credentials.

6. Privacy and Information

6.1 In order to continually innovate and improve the SDK, Google may collect certain usage statistics from the software including but not limited to a unique identifier, associated IP address, version number of the software, and information on which tools and/or services in the SDK are being used and how they are being used. Before any of this information is collected, the SDK will notify you and seek your consent. If you withhold consent, the information will not be collected.

6.2 The data collected is examined in the aggregate to improve the SDK and is maintained in accordance with Google's Privacy Policy.


7. Third Party Applications

7.1 If you use the SDK to run applications developed by a third party or that access data, content or resources provided by a third party, you agree that Google is not responsible for those applications, data, content, or resources. You understand that all data, content or resources which you may access through such third party applications are the sole responsibility of the person from which they originated and that Google is not liable for any loss or damage that you may experience as a result of the use or access of any of those third party applications, data, content, or resources.

7.2 You should be aware the data, content, and resources presented to you through such a third party application may be protected by intellectual property rights which are owned by the providers (or by other persons or companies on their behalf). You may not modify, rent, lease, loan, sell, distribute or create derivative works based on these data, content, or resources (either in whole or in part) unless you have been specifically given permission to do so by the relevant owners.

7.3 You acknowledge that your use of such third party applications, data, content, or resources may be subject to separate terms between you and the relevant third party. In that case, the License Agreement does not affect your legal relationship with these third parties.


8. Using Android APIs

8.1 Google Data APIs

8.1.1 If you use any API to retrieve data from Google, you acknowledge that the data may be protected by intellectual property rights which are owned by Google or those parties that provide the data (or by other persons or companies on their behalf). Your use of any such API may be subject to additional Terms of Service. You may not modify, rent, lease, loan, sell, distribute or create derivative works based on this data (either in whole or in part) unless allowed by the relevant Terms of Service.

8.1.2 If you use any API to retrieve a user's data from Google, you acknowledge and agree that you shall retrieve data only with the user's explicit consent and only when, and for the limited purposes for which, the user has given you permission to do so. If you use the Android Recognition Service API, documented at the following URL: https://developer.android.com/reference/android/speech/RecognitionService, as updated from time to time, you acknowledge that the use of the API is subject to the Data Processing Addendum for Products where Google is a Data Processor, which is located at the following URL: https://privacy.google.com/businesses/gdprprocessorterms/, as updated from time to time. By clicking to accept, you hereby agree to the terms of the Data Processing Addendum for Products where Google is a Data Processor.


9. Terminating the License Agreement

9.1 The License Agreement will continue to apply until terminated by either you or Google as set out below.

9.2 If you want to terminate the License Agreement, you may do so by ceasing your use of the SDK and any relevant developer credentials.

9.3 Google may at any time, terminate the License Agreement with you if: (A) you have breached any provision of the License Agreement; or (B) Google is required to do so by law; or (C) the partner with whom Google offered certain parts of SDK (such as APIs) to you has terminated its relationship with Google or ceased to offer certain parts of the SDK to you; or (D) Google decides to no longer provide the SDK or certain parts of the SDK to users in the country in which you are resident or from which you use the service, or the provision of the SDK or certain SDK services to you by Google is, in Google's sole discretion, no longer commercially viable.

9.4 When the License Agreement comes to an end, all of the legal rights, obligations and liabilities that you and Google have benefited from, been subject to (or which have accrued over time whilst the License Agreement has been in force) or which are expressed to continue indefinitely, shall be unaffected by this cessation, and the provisions of paragraph 14.7 shall continue to apply to such rights, obligations and liabilities indefinitely.


10. DISCLAIMER OF WARRANTIES

10.1 YOU EXPRESSLY UNDERSTAND AND AGREE THAT YOUR USE OF THE SDK IS AT YOUR SOLE RISK AND THAT THE SDK IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTY OF ANY KIND FROM GOOGLE.

10.2 YOUR USE OF THE SDK AND ANY MATERIAL DOWNLOADED OR OTHERWISE OBTAINED THROUGH THE USE OF THE SDK IS AT YOUR OWN DISCRETION AND RISK AND YOU ARE SOLELY RESPONSIBLE FOR ANY DAMAGE TO YOUR COMPUTER SYSTEM OR OTHER DEVICE OR LOSS OF DATA THAT RESULTS FROM SUCH USE.

10.3 GOOGLE FURTHER EXPRESSLY DISCLAIMS ALL WARRANTIES AND CONDITIONS OF ANY KIND, WHETHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO THE IMPLIED WARRANTIES AND CONDITIONS OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.


11. LIMITATION OF LIABILITY

11.1 YOU EXPRESSLY UNDERSTAND AND AGREE THAT GOOGLE, ITS SUBSIDIARIES AND AFFILIATES, AND ITS LICENSORS SHALL NOT BE LIABLE TO YOU UNDER ANY THEORY OF LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL OR EXEMPLARY DAMAGES THAT MAY BE INCURRED BY YOU, INCLUDING ANY LOSS OF DATA, WHETHER OR NOT GOOGLE OR ITS REPRESENTATIVES HAVE BEEN ADVISED OF OR SHOULD HAVE BEEN AWARE OF THE POSSIBILITY OF ANY SUCH LOSSES ARISING.


12. Indemnification

12.1 To the maximum extent permitted by law, you agree to defend, indemnify and hold harmless Google, its affiliates and their respective directors, officers, employees and agents from and against any and all claims, actions, suits or proceedings, as well as any and all losses, liabilities, damages, costs and expenses (including reasonable attorneys fees) arising out of or accruing from (a) your use of the SDK, (b) any application you develop on the SDK that infringes any copyright, trademark, trade secret, trade dress, patent or other intellectual property right of any person or defames any person or violates their rights of publicity or privacy, and (c) any non-compliance by you with the License Agreement.


13. Changes to the License Agreement

13.1 Google may make changes to the License Agreement as it distributes new versions of the SDK. When these changes are made, Google will make a new version of the License Agreement available on the website where the SDK is made available.


14. General Legal Terms

14.1 The License Agreement constitutes the whole legal agreement between you and Google and governs your use of the SDK (excluding any services which Google may provide to you under a separate written agreement), and completely replaces any prior agreements between you and Google in relation to the SDK.

14.2 You agree that if Google does not exercise or enforce any legal right or remedy which is contained in the License Agreement (or which Google has the benefit of under any applicable law), this will not be taken to be a formal waiver of Google's rights and that those rights or remedies will still be available to Google.

14.3 If any court of law, having the jurisdiction to decide on this matter, rules that any provision of the License Agreement is invalid, then that provision will be removed from the License Agreement without affecting the rest of the License Agreement. The remaining provisions of the License Agreement will continue to be valid and enforceable.

14.4 You acknowledge and agree that each member of the group of companies of which Google is the parent shall be third party beneficiaries to the License Agreement and that such other companies shall be entitled to directly enforce, and rely upon, any provision of the License Agreement that confers a benefit on (or rights in favor of) them. Other than this, no other person or company shall be third party beneficiaries to the License Agreement.

14.5 EXPORT RESTRICTIONS. THE SDK IS SUBJECT TO UNITED STATES EXPORT LAWS AND REGULATIONS. YOU MUST COMPLY WITH ALL DOMESTIC AND INTERNATIONAL EXPORT LAWS AND REGULATIONS THAT APPLY TO THE SDK. THESE LAWS INCLUDE RESTRICTIONS ON DESTINATIONS, END USERS AND END USE.

14.6 The rights granted in the License Agreement may not be assigned or transferred by either you or Google without the prior written approval of the other party. Neither you nor Google shall be permitted to delegate their responsibilities or obligations under the License Agreement without the prior written approval of the other party.

14.7 The License Agreement, and your relationship with Google under the License Agreement, shall be governed by the laws of the State of California without regard to its conflict of laws provisions. You and Google agree to submit to the exclusive jurisdiction of the courts located within the county of Santa Clara, California to resolve any legal matter arising from the License Agreement. Notwithstanding this, you agree that Google shall still be allowed to apply for injunctive remedies (or an equivalent type of urgent legal relief) in any jurisdiction.


January 16, 2019"""

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
    d = {
        'license': ANDROID_SDK_LICENSE,
        'license_id': 'android-sdk-license',
        'path': package,
        'revision': ''.join(template[:r]).format(*revision),
    }
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
