Guided Fuzzing Daemon
=====================
[![Python CI](https://github.com/MozillaSecurity/guided-fuzzing-daemon/actions/workflows/ci.yml/badge.svg)](https://github.com/MozillaSecurity/guided-fuzzing-daemon/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MozillaSecurity/guided-fuzzing-daemon/branch/main/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/guided-fuzzing-daemon)
[![Matrix](https://img.shields.io/badge/chat-%23fuzzing-green?logo=matrix)](https://matrix.to/#/#fuzzing:mozilla.org)

Guided Fuzzing Daemon is a wrapper around running and reporting issues from
coverage-guided fuzzers such as libFuzzer, AFL++, Nyx, or Fuzzilli. Corpora can be
stored in a cloud-provider such as S3 or GCS, and crashes reported to FuzzManager.
