#!/usr/bin/env python3

import glob
import os
import sdkmanager
import unittest


class SdkManagerTest(unittest.TestCase):
    """test the core sdkmanager functions"""

    def setUp(self):
        self.tests_dir = os.path.join(os.path.dirname(__file__), 'tests')

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


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    newSuite = unittest.TestSuite()
    newSuite.addTest(unittest.makeSuite(SdkManagerTest))
    unittest.main(failfast=False)
