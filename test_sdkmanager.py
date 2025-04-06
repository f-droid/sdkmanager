#!/usr/bin/env python3

import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from zipfile import ZipFile, ZipInfo

import requests
from defusedxml import ElementTree

import sdkmanager


class SdkManagerTest(unittest.TestCase):
    """test the core sdkmanager functions"""

    @classmethod
    def setUpClass(cls):
        # this isolates the tests from the local env, but not from each other
        cls.isolate_home = tempfile.TemporaryDirectory()
        cls.env_patcher = mock.patch.dict(
            os.environ, {'HOME': cls.isolate_home.name}, clear=True
        )
        cls.env_patcher.start()
        cls.initial_tests_dir = Path(__file__).resolve().parent / 'tests'
        try:
            import requests_cache

            cache = os.path.join(tempfile.gettempdir(), 'SdkManagerTest_cache')
            print('Using %s as Requests download cache' % cache)
            requests_cache.install_cache(cache)
        except ImportError:
            pass

    @classmethod
    def tearDownClass(cls):
        cls.env_patcher.stop()
        cls.isolate_home.cleanup()

    def setUp(self):
        os.chdir(os.path.dirname(__file__))
        self.tests_dir = self.initial_tests_dir
        self.temp_sdk_dir = tempfile.TemporaryDirectory()
        self.sdk_dir = Path(self.temp_sdk_dir.name)
        self.assertTrue(self.sdk_dir.exists())

        self.temp_home = tempfile.TemporaryDirectory()
        self.cachedir = Path(self.temp_home.name) / '.cache/sdkmanager'
        self.cachedir.mkdir(parents=True)
        sdkmanager.get_cachedir = lambda: self.cachedir

        os.environ['HOME'] = self.temp_home.name

        sdkmanager.packages = {}
        sdkmanager.revisions = {}
        sdkmanager.platform_versions = {}

    def tearDown(self):
        self.temp_home.cleanup()
        self.temp_sdk_dir.cleanup()

    @mock.patch.dict(os.environ)
    def test_get_android_home_fail(self):
        os.environ['ANDROID_HOME'] = 'nonexistent/android-sdk'
        with self.assertRaises(FileNotFoundError):
            sdkmanager.get_android_home()

    def test_package_xml_template(self):
        with (self.tests_dir / 'checksums.json').open() as fp:
            sdkmanager._process_checksums(json.load(fp))
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
            ('ndk;r10e', 'android-ndk-r10e-linux-x86_64.zip', (10, 4)),
        ):
            install_dir = self.sdk_dir / 'install_dir' / package.split(';')[0]
            install_dir.mkdir(parents=True, exist_ok=True)
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
            self.assertEqual(result[0], int(major.text))

    def test_ndk_package_xml_version(self):
        with (self.tests_dir / 'checksums.json').open() as fp:
            sdkmanager._process_checksums(json.load(fp))

        def get_package_xml(package):
            url = 'https://dl.google.com/android/repository/android-ndk-r25c-linux.zip'
            install_dir = self.sdk_dir / 'install_dir' / package.split(';')[1]
            install_dir.mkdir(parents=True)
            sdkmanager._generate_package_xml(install_dir, package, url)
            return (install_dir / 'package.xml').read_text()

        self.assertEqual(
            get_package_xml('ndk;25.2.9519653'), get_package_xml('ndk;r25c')
        )

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

        url = 'https://dl.google.com/android/repository/android-ndk-r28-beta1-linux.zip'
        self.assertEqual(url, sdkmanager.packages[('ndk', 'r28-beta1')])
        self.assertEqual((28, 0, 12433566), sdkmanager.revisions[url])

        url = (
            'https://dl.google.com/android/repository/android-ndk-r10e-linux-x86_64.zip'
        )
        self.assertEqual(url, sdkmanager.packages[('ndk', 'r10e')])
        self.assertEqual((10, 4), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/android-2.3.1_r02.zip'
        self.assertEqual(url, sdkmanager.packages[('platforms', 'android-9')])
        self.assertEqual((2,), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/commandlinetools-linux-7583922_latest.zip'
        self.assertEqual(url, sdkmanager.packages[('cmdline-tools', '5.0')])
        self.assertEqual((5, 0), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/commandlinetools-linux-12700392_latest.zip'
        self.assertEqual(url, sdkmanager.packages[('cmdline-tools', 'latest')])
        self.assertEqual((17, 0), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/skiaparser-7478287-linux.zip'
        self.assertEqual(url, sdkmanager.packages[('skiaparser', '2')])
        self.assertEqual((3,), sdkmanager.revisions[url])

        url = 'https://dl.google.com/android/repository/emulator-linux_x64-7226809.zip'
        self.assertEqual(url, sdkmanager.packages[('emulator', '30.6.1')])
        self.assertEqual((30, 6, 1), sdkmanager.revisions[url])

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

    @mock.patch.dict(os.environ)
    def test_licenses(self):
        os.environ['ANDROID_HOME'] = str(self.sdk_dir)
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

    @mock.patch('sdkmanager.get_android_home')
    @mock.patch('sdkmanager.download_file', mock.Mock())
    @mock.patch('sdkmanager._install_zipball_from_cache', mock.Mock())
    @mock.patch('sdkmanager._generate_package_xml', mock.Mock())
    def test_install_android_home_arg(self, get_android_home):
        """Install can optionally handle getting ANDROID_HOME as arg"""
        url = 'https://dl.google.com/android/repository/android-ndk-r24-linux.zip'
        sdkmanager.packages = {('ndk', 'r24'): url}
        local_sdk_dir = Path(self.temp_sdk_dir.name) / 'local_sdk_dir'
        local_ndk_dir = local_sdk_dir / 'ndk'
        self.assertFalse(local_ndk_dir.exists())
        sdkmanager.install('ndk;r24', local_sdk_dir)
        get_android_home.assert_not_called()
        self.assertTrue(local_ndk_dir.exists())

    @mock.patch('sdkmanager.download_file', mock.Mock())
    @mock.patch('sdkmanager._install_zipball_from_cache', mock.Mock())
    @mock.patch('sdkmanager._generate_package_xml', mock.Mock())
    @mock.patch.dict(os.environ)
    def test_install_set_android_home(self):
        """Install should find ANDROID_HOME and create the ndk dir"""
        os.environ['ANDROID_HOME'] = str(self.sdk_dir)
        url = 'https://dl.google.com/android/repository/android-ndk-r24-linux.zip'
        sdkmanager.packages = {('ndk', 'r24'): url}
        ndk_dir = self.sdk_dir / 'ndk'
        self.assertFalse(ndk_dir.exists())
        sdkmanager.install('ndk;r24')
        self.assertTrue(ndk_dir.exists())

    @mock.patch('sdkmanager.download_file', mock.Mock())
    @mock.patch('sdkmanager._install_zipball_from_cache', mock.Mock())
    @mock.patch('sdkmanager._generate_package_xml')
    @mock.patch.dict(os.environ)
    def test_install_ndk_dir_layout(self, _generate_package_xml):
        """Should install the NDK using the right version as the dir name."""

        # pylint: disable=unused-argument
        def mock_generate_package_xml(install_dir, package, url):
            self.assertFalse(install_dir.name.startswith('r'))

        _generate_package_xml.side_effect = mock_generate_package_xml
        with (self.tests_dir / 'checksums.json').open() as fp:
            sdkmanager._process_checksums(json.load(fp))
        os.environ['ANDROID_HOME'] = str(self.sdk_dir)
        url = 'https://dl.google.com/android/repository/android-ndk-r24-linux.zip'
        sdkmanager.packages = {('ndk', 'r24'): url}
        ndk_dir = self.sdk_dir / 'ndk'
        self.assertFalse(ndk_dir.exists())
        sdkmanager.install('ndk;r24')
        self.assertTrue(ndk_dir.exists())
        _generate_package_xml.assert_called()

    @mock.patch.dict(os.environ)
    def test_install_and_rerun(self):
        """Install should work and rerunning should not change the install"""
        os.environ['ANDROID_HOME'] = str(self.sdk_dir)

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

                zip_info = ZipInfo(str(zipdir / 'basename'))
                zip_info.create_system = 3
                zip_info.external_attr = unix_st_mode << 16
                zipfp.writestr(zip_info, os.path.basename(testfile))

                zip_info = ZipInfo(str(zipdir / 'executable'))
                zip_info.create_system = 3
                zip_info.external_attr = stat.S_IXUSR << 16
                zipfp.writestr(zip_info, '!#/bin/sh\necho This is an executable file\n')

                zip_info = ZipInfo(str(zipdir / 'bad_abs_link'))
                zip_info.create_system = 3
                zip_info.external_attr = unix_st_mode << 16
                zipfp.writestr(zip_info, '/etc/passwd')

                zip_info = ZipInfo(str(zipdir / 'bad_rel_link'))
                zip_info.create_system = 3
                zip_info.external_attr = unix_st_mode << 16
                zipfp.writestr(zip_info, '../../../../../../../etc/passwd')

                # zipfp.writestr(str(zipdir / 'foo/mkdir'), 'shorthand to create the foo dir')
                zip_info = ZipInfo(str(zipdir / 'bad_rel_link2'))
                zip_info.create_system = 3
                zip_info.external_attr = unix_st_mode << 16
                zipfp.writestr(zip_info, 'foo/../../../../../../../../../etc/passwd')

            install_dir = Path(tmpdir) / 'install_dir'
            sdkmanager._install_zipball_from_cache(zipball, install_dir)

            self.assertTrue(install_dir.exists())
            self.assertTrue((install_dir / 'basename').exists())
            self.assertFalse((install_dir / 'bad_abs_link').exists())
            self.assertFalse((install_dir / 'bad_rel_link').exists())
            self.assertFalse((install_dir / 'bad_rel_link2').exists())

    def test_checksums_json_mirrors(self):
        """If this fails on a size error, update the local committed checksums.json."""
        cachedir = sdkmanager.get_cachedir()
        for url in sdkmanager.CHECKSUMS_URLS:
            print(url)
            urldir = cachedir / url.replace('https://', '').replace('/', '_')
            urldir.mkdir()
            os.chdir(str(urldir))

            r = requests.get(url)
            r.raise_for_status()
            with open('checksums.json', 'w') as fp:
                json.dump(r.json(), fp)

            r = requests.get(url + '.asc')
            r.raise_for_status()
            with open('checksums.json.asc', 'w') as fp:
                fp.write(r.text)
        size = None
        for f in cachedir.glob('*/checksums.json'):
            if size is None:
                size = f.stat().st_size
            self.assertEqual(size, f.stat().st_size)
        size = None
        for f in cachedir.glob('*/checksums.json.asc'):
            if size is None:
                size = f.stat().st_size
            self.assertEqual(size, f.stat().st_size)

    def test_get_properties_dict(self):
        """Sometimes the Android Tools releases have strange stuff in them."""
        for s in (
            # fake manually generated data
            "Pkg.UserSrc=true\nPkg.UserSrc=false\nPkg.Revision=17.0.0\n\n",
            # https://dl.google.com/android/repository/build-tools_r17-linux.zip
            "Pkg.UserSrc=false\nPkg.Revision=17.0.0\n\n",
            # https://dl.google.com/android/repository/build-tools_r35.0.1_linux.zip
            "Pkg.UserSrc=false\nPkg.UserSrc=false\nPkg.Revision=35.0.1\n#Pkg.Revision=35.0.0 rc4\n",
            # https://dl.google.com/android/repository/platform-33_r01.zip
            "Pkg.Desc=Android SDK Platform 13\nPkg.UserSrc=false\nPlatform.Version=13\nPlatform.CodeName=\nPkg.Revision=1\nAndroidVersion.ApiLevel=33\nAndroidVersion.ExtensionLevel=3\nAndroidVersion.IsBaseSdk=true\nLayoutlib.Api=15\nLayoutlib.Revision=1\nPlatform.MinToolsRev=22\n",
        ):
            d = sdkmanager.get_properties_dict(s)
            self.assertEqual('false', d['pkg.usersrc'])

    def test_get_properties_dict_uses_last_value(self):
        """This test just demonstrates the behavior."""
        d = sdkmanager.get_properties_dict("Pkg.UserSrc=false\nPkg.UserSrc=true\n")
        self.assertEqual('true', d['pkg.usersrc'])
        d = sdkmanager.get_properties_dict("Pkg.UserSrc=true\nPkg.UserSrc=false\n")
        self.assertEqual('false', d['pkg.usersrc'])

    def test_build_package_list_exception_on_verify_fail(self):
        """If checksums.json signature fails to verify, delete it so it tries again."""
        checksums_json = Path(self.cachedir) / 'checksums.json'
        checksums_json.write_text('{"json": "value"}')
        checksums_json_asc = Path(self.cachedir) / 'checksums.json.asc'
        checksums_json_asc.write_text('fake sig')
        with self.assertRaises(RuntimeError):
            sdkmanager.build_package_list()
        self.assertFalse(checksums_json.exists())
        self.assertFalse(checksums_json_asc.exists())

    @mock.patch('sdkmanager.verify', mock.Mock())
    def test_build_package_list_rm_checksums_json_on_error(self):
        """If checksums.json is corrupt, delete it so it tries again."""
        checksums_json = Path(self.cachedir) / 'checksums.json'
        checksums_json.write_text('{"corrupt json": ')
        checksums_json_asc = Path(self.cachedir) / 'checksums.json.asc'
        checksums_json_asc.write_text('fake sig')
        sdkmanager.build_package_list()
        self.assertFalse(checksums_json.exists())
        self.assertFalse(checksums_json_asc.exists())
