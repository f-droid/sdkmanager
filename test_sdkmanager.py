#!/usr/bin/env python3

import os
import sdkmanager
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class SdkManagerTest(unittest.TestCase):
    """test the core sdkmanager functions"""

    def setUp(self):
        self.tests_dir = os.path.join(os.path.dirname(__file__), 'tests')
        self.sdk_dir = Path(tempfile.mkdtemp(prefix='.test_sdkmanager-android-sdk-'))
        self.assertTrue(self.sdk_dir.exists())
        sdkmanager.ANDROID_SDK_ROOT = self.sdk_dir

    def test_parse_repositories_cfg(self):
        rc = sdkmanager.parse_repositories_cfg(
            os.path.join(self.tests_dir, 'disabled-repositories.cfg')
        )
        self.assertEqual([], rc)

        rc = sdkmanager.parse_repositories_cfg(
            os.path.join(self.tests_dir, 'simple-repositories.cfg')
        )
        self.assertEqual(['https://staging.f-droid.org/emulator/sys-img.xml'], rc)

        rc = sdkmanager.parse_repositories_cfg(
            os.path.join(self.tests_dir, 'two-extras-repositories.cfg')
        )
        self.assertEqual(
            [
                'https://microg.org/sdk/sys-img.xml',
                'https://release.calyxinstitute.org/sys-img.xml',
            ],
            rc,
        )

    def test_main_args(self):
        for command in ['list', 'install']:
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

    def test_install(self):
        with mock.patch('sys.argv', ['', 'build-tools;17.0.0']):
            sdkmanager.main()
        self.assertTrue((self.sdk_dir / 'build-tools/17.0.0/aapt').exists())


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    newSuite = unittest.TestSuite()
    newSuite.addTest(unittest.makeSuite(SdkManagerTest))
    unittest.main(failfast=False)
