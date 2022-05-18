#!/usr/bin/env python3

import io
import json
import os
import sdkmanager
import shutil
import stat
import tempfile
import unittest
from defusedxml import ElementTree
from pathlib import Path
from unittest import mock
from zipfile import ZipFile, ZipInfo


class SdkManagerTest(unittest.TestCase):
    """test the core sdkmanager functions"""

    @classmethod
    def setUpClass(cls):
        cls.initial_tests_dir = Path(__file__).resolve().parent / 'tests'
        try:
            import requests_cache

            cache = os.path.join(tempfile.gettempdir(), 'SdkManagerTest_cache')
            print('Using %s as Requests download cache' % cache)
            requests_cache.install_cache(cache)
        except ImportError:
            pass

    def setUp(self):
        self.tests_dir = self.initial_tests_dir
        self.temp_sdk_dir = tempfile.TemporaryDirectory()
        self.sdk_dir = Path(self.temp_sdk_dir.name)
        self.assertTrue(self.sdk_dir.exists())
        sdkmanager.ANDROID_SDK_ROOT = self.sdk_dir
        os.environ.pop('ANDROID_SDK_ROOT', None)
        os.environ.pop('ANDROID_HOME', None)

        self.temp_home = tempfile.TemporaryDirectory()
        sdkmanager.CACHEDIR = Path(self.temp_home.name) / '.cache/sdkmanager'
        sdkmanager.CACHEDIR.mkdir(parents=True)
        os.environ['HOME'] = self.temp_home.name

    def tearDown(self):
        self.temp_home.cleanup()
        self.temp_sdk_dir.cleanup()

    def test_package_xml_template(self):
        self.assertEqual(
            "<",
            sdkmanager.GENERIC_PACKAGE_XML_TEMPLATE[0],
            "no whitespace at start of XML",
        )
        self.assertEqual(
            ">",
            sdkmanager.GENERIC_PACKAGE_XML_TEMPLATE[-1],
            "no whitespace at end of XML",
        )
        baseurl = 'https://dl.google.com/android/repository/'
        for package, f, result in (
            ('build-tools;28.0.1', 'build-tools_r28.0.1-linux.zip', (28, 0, 1)),
            ('cmake;3.10.2.4988404', 'cmake-3.10.2-linux-x86_64.zip', (3, 10, 2)),
            ('ndk;22.1.7171670', 'android-ndk-r22b-linux-x86_64.zip', (22, 1, 7171670)),
        ):
            install_dir = self.sdk_dir / 'install_dir' / package.split(';')[0]
            install_dir.mkdir(parents=True)
            sdkmanager._generate_package_xml(install_dir, package, baseurl + f)
            package_xml = install_dir / 'package.xml'
            self.assertTrue(
                package_xml.exists(), '_generate_package_xml() creates package.xml'
            )
            root = ElementTree.parse(str(package_xml)).getroot()
            revision = root.find('./localPackage/revision')
            self.assertIsNotNone(revision, 'package.xml must contain <revision>')
            major = revision.find('major')
            self.assertIsNotNone(major, '<revision> must contain <major>')
            self.assertEqual(package.split(';')[1].split('.')[0], major.text)
            self.assertEqual(result[0], int(major.text))

    def test_parse_repositories_cfg(self):
        rc = sdkmanager.parse_repositories_cfg(
            self.tests_dir / 'disabled-repositories.cfg'
        )
        self.assertEqual([], rc)

        rc = sdkmanager.parse_repositories_cfg(
            self.tests_dir / 'simple-repositories.cfg'
        )
        self.assertEqual(['https://staging.f-droid.org/emulator/sys-img.xml'], rc)

        rc = sdkmanager.parse_repositories_cfg(
            self.tests_dir / 'two-extras-repositories.cfg'
        )
        self.assertEqual(
            [
                'https://microg.org/sdk/sys-img.xml',
                'https://release.calyxinstitute.org/sys-img.xml',
            ],
            rc,
        )

    def test_process_checksums(self):
        with (self.tests_dir / 'checksums.json').open() as fp:
            sdkmanager._process_checksums(json.load(fp))
        self.assertTrue(('tools',) in sdkmanager.packages)
        self.assertTrue(('platform-tools',) in sdkmanager.packages)

        url = 'https://dl.google.com/android/repository/platform-29_r05.zip'
        self.assertEqual(url, sdkmanager.packages[('platforms', 'android-29')])
        self.assertEqual((5,), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/platform-31_r01.zip'
        self.assertEqual(url, sdkmanager.packages[('platforms', 'android-31')])
        self.assertEqual((1,), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/android_m2repository_r47.zip'
        self.assertEqual(
            url, sdkmanager.packages[('extras', 'android', 'm2repository', '47')]
        )
        self.assertEqual((47, 0, 0), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/android-ndk-r24-linux.zip'
        self.assertEqual(url, sdkmanager.packages[('ndk', 'r24')])
        self.assertEqual((24, 0, 8215888), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/android-2.3.1_r02.zip'
        self.assertEqual(url, sdkmanager.packages[('platforms', 'android-9')])
        self.assertEqual((2,), sdkmanager.revisions[url])

    def test_ndk_release_regex(self):
        with (self.tests_dir / 'checksums.json').open() as fp:
            urls = json.load(fp).keys()
        found_versions = []
        for url in urls:
            if '-ndk-' in url and 'r24' in url:
                m = sdkmanager.NDK_RELEASE_REGEX.search(url)
                if m:
                    found_versions.append(m.group())
        self.assertEqual(
            ['r24', 'r24-beta1', 'r24-beta2', 'r24-rc1'], sorted(found_versions)
        )

    def test_main_args(self):
        for command in ['install', 'licenses', 'list']:
            with mock.patch('sys.argv', ['', '--' + command]):
                with mock.patch('sdkmanager.' + command) as function:
                    sdkmanager.main()
                    self.assertEqual(1, function.call_count)

        with mock.patch('sdkmanager.install') as function:
            self.assertEqual(0, function.call_count)
            with mock.patch('sys.argv', ['', 'ndk;r10']):
                sdkmanager.main()
                self.assertEqual(1, function.call_count)
            with mock.patch('sys.argv', ['', 'ndk;r21e', 'build-tools;29.0.3']):
                sdkmanager.main()
                self.assertEqual(2, function.call_count)

    def test_licenses(self):
        licenses_dir = self.sdk_dir / 'licenses'
        self.assertFalse(licenses_dir.exists())
        with mock.patch('sys.argv', ['', '--licenses']):
            with mock.patch('sys.stdin', io.StringIO('n\n')) as stdin:
                sdkmanager.main()
                self.assertEqual('', stdin.read(), "all input consumed")
                self.assertFalse(licenses_dir.exists())
            with mock.patch('sys.stdin', io.StringIO('y\n')) as stdin:
                sdkmanager.main()
                self.assertEqual('', stdin.read(), "all input consumed")
                self.assertTrue(licenses_dir.exists())
                self.assertEqual(4, len(list(licenses_dir.glob('*'))))

    def test_install_and_rerun(self):
        """install should work and rerunning should not change the install"""
        # toplevels == 1
        with mock.patch('sys.argv', ['', 'build-tools;17.0.0']):
            sdkmanager.main()
        aapt = self.sdk_dir / 'build-tools/17.0.0/aapt'
        self.assertTrue(aapt.exists())
        aapt.unlink()
        self.assertFalse(aapt.exists())
        with mock.patch('sys.argv', ['', 'build-tools;17.0.0']):
            sdkmanager.main()
        self.assertFalse(aapt.exists())

        # toplevels > 1
        with mock.patch('sys.argv', ['', 'cmake;3.18.1']):
            sdkmanager.main()
        cmake = self.sdk_dir / 'cmake/3.18.1/bin/cmake'
        self.assertTrue(cmake.exists())
        cmake.unlink()
        self.assertFalse(cmake.exists())
        with mock.patch('sys.argv', ['', 'cmake;3.18.1']):
            sdkmanager.main()
        self.assertFalse(cmake.exists())

    def test_verify(self):
        checksums = self.tests_dir / 'checksums.json'
        sdkmanager.verify(checksums)
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            shutil.copy(str(checksums.resolve()) + '.asc', 'checksums.json.asc')
            with open('checksums.json', 'w') as fp:
                fp.write('this is a placeholder that should not work')
            with self.assertRaises(RuntimeError):
                sdkmanager.verify('checksums.json')

            open('zerofile', 'w').close()
            open('zerofile.asc', 'w').close()
            with self.assertRaises(RuntimeError):
                sdkmanager.verify('zerofile')

    def test_install_with_symlinks(self):
        """Some NDK zipballs might have symlinks in them."""

        zipdir = Path('android-ndk-r22b')
        zipball = Path(str(zipdir) + '-linux-x86_64.zip')
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            unix_st_mode = (
                stat.S_IFLNK
                | stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IWGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IWOTH
                | stat.S_IXOTH
            )
            with ZipFile(str(zipball), 'w') as zipfp:
                testfile = str(zipdir / 'testfile')
                zipfp.writestr(testfile, 'This is just a test!')

                zipInfo = ZipInfo(str(zipdir / 'basename'))
                zipInfo.create_system = 3
                zipInfo.external_attr = unix_st_mode << 16
                zipfp.writestr(zipInfo, os.path.basename(testfile))

                zipInfo = ZipInfo(str(zipdir / 'executable'))
                zipInfo.create_system = 3
                zipInfo.external_attr = stat.S_IXUSR << 16
                zipfp.writestr(zipInfo, '!#/bin/sh\necho This is an executable file\n')

                zipInfo = ZipInfo(str(zipdir / 'bad_abs_link'))
                zipInfo.create_system = 3
                zipInfo.external_attr = unix_st_mode << 16
                zipfp.writestr(zipInfo, '/etc/passwd')

                zipInfo = ZipInfo(str(zipdir / 'bad_rel_link'))
                zipInfo.create_system = 3
                zipInfo.external_attr = unix_st_mode << 16
                zipfp.writestr(zipInfo, '../../../../../../../etc/passwd')

                # zipfp.writestr(str(zipdir / 'foo/mkdir'), 'shorthand to create the foo dir')
                zipInfo = ZipInfo(str(zipdir / 'bad_rel_link2'))
                zipInfo.create_system = 3
                zipInfo.external_attr = unix_st_mode << 16
                zipfp.writestr(zipInfo, 'foo/../../../../../../../../../etc/passwd')

            install_dir = Path(tmpdir) / 'install_dir'
            sdkmanager._install_zipball_from_cache(zipball, install_dir)

            self.assertTrue(install_dir.exists())
            self.assertTrue((install_dir / 'basename').exists())
            self.assertFalse((install_dir / 'bad_abs_link').exists())
            self.assertFalse((install_dir / 'bad_rel_link').exists())
            self.assertFalse((install_dir / 'bad_rel_link2').exists())


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    newSuite = unittest.TestSuite()
    newSuite.addTest(unittest.makeSuite(SdkManagerTest))
    unittest.main(failfast=False)
