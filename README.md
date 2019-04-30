buildkite-webhook-listener
==========================

Simple flask listener which will wait for buildkite webhook pokes, and when it
gets one, downloads an artifact and unpacks it.

For more details, see `--help`.

TODO: add a hook so that we can do more complex unpacking.
