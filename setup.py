#!/usr/bin/env python3

from setuptools import Command, setup
import subprocess
import sys


class VersionCheckCommand(Command):
    """Make sure git tag and version match before uploading"""

    user_options = []

    def initialize_options(self):
        """Abstract method that is required to be overwritten"""

    def finalize_options(self):
        """Abstract method that is required to be overwritten"""

    def run(self):
        version = self.distribution.get_version()
        version_git = (
            subprocess.check_output(['git', 'describe', '--tags', '--always'])
            .rstrip()
            .decode('utf-8')
        )
        if version != version_git:
            print(
                'ERROR: Release version mismatch! setup.py (%s) does not match git (%s)'
                % (version, version_git)
            )
            sys.exit(1)
        print('Upload using: twine upload --sign dist/sdkmanager-%s.tar.gz' % version)


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='sdkmanager',
    version='0.6.7',
    description='Android SDK Manager',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='The F-Droid Project',
    author_email='team@f-droid.org',
    url='https://gitlab.com/fdroid/sdkmanager',
    license='AGPL-3.0',
    py_modules=['sdkmanager'],
    entry_points={'console_scripts': ['sdkmanager=sdkmanager:main']},
    python_requires='>=3.5',
    cmdclass={'versioncheck': VersionCheckCommand},
    install_requires=[
        "argcomplete",
        "requests > 2.12.2, != 2.18.0",
        "urllib3<2",
        'looseversion; python_version>="3.12"',
    ],
    extras_require={'test': ['defusedxml', 'requests-cache']},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Software Development',
        'Topic :: Utilities',
    ],
)
