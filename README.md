
A drop-in replacement for `sdkmanager` from the Android SDK written in Python.
It implements the exact API of the
[`sdkmanager`](https://developer.android.com/studio/command-line/sdkmanager)
command line.  It only deviates from that API if it can be done while being 100%
compatible.

The project also attempts to maintain the same terminal output so it can be
compatible with things that scrape `sdkmanager` output.


## Code Format

This project uses Black to automatically format all the Python code.  It uses
the version of Black that is in Debian/stable.  To format the code, run:

```bash
black --skip-string-normalization *.py
```
