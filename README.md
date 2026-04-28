
A drop-in replacement for `sdkmanager` from the Android SDK written in Python.
It implements the exact API of the
[`sdkmanager`](https://developer.android.com/studio/command-line/sdkmanager)
command line.  It only deviates from that API if it can be done while being 100%
compatible.

The project also attempts to maintain the same terminal output so it can be
compatible with things that scrape `sdkmanager` output.

## Architecture

This was designed around the idea that each SDK package contains all the relevant metadata in it, e.g. _source.properties_.  So the _checksums.json_ index file was designed just to be the index of those package files.  This is how F-Droid and Debian indexes work.  It looks like Google's `sdkmanager` was designed with that idea, but sadly, the maintainers of Google's `sdkmanager` have not been faithful to it.  Some values like "display-name" are only available in the index files, e.g. _repository2-3.xml_. Even worse, the SDK packages contain something similar, `Pkg.Desc`, but it has strange conflicting values.

Also, since XML is a nightmare and this `sdkmanager` is written in Python, this `sdkmanager` was designed to use JSON as much as possible.

## Key sources

The AOSP source code is hard to navigate for many reasons.  Here are a couple of entry points for info relevant to this project:

* _source.properties_ templates:
  https://android.googlesource.com/platform/development/+/refs/tags/android-16.0.0_r4/sdk/
* _repository2-x.xml_ templates:
  https://android.googlesource.com/platform/tools/base/+/1fd0588c0b284453faea362de4d22b2c5e5f1a70/sdklib/src/main/resources/xsd/


## Code Format

This project uses Black to automatically format all the Python code.  It uses
the version of Black that is in Debian/stable.  To format the code, run:

```bash
black --skip-string-normalization *.py
```
