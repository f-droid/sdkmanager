
A drop-in replacement for `sdkmanager` from the Android SDK written in Python.
It implements the exact API of the
[`sdkmanager`](https://developer.android.com/studio/command-line/sdkmanager)
command line.  It only deviates from that API if it can be done while being 100%
compatible.

The project also attempts to maintain the same terminal output so it can be
compatible with things that scrape `sdkmanager` output.
