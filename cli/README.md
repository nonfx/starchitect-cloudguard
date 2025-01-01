# starkit

Starkit is a CLI to run tests against your Cloud accounts or your IAC files.

[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![Version](https://img.shields.io/npm/v/mynewcli.svg)](https://npmjs.org/package/mynewcli)
[![Downloads/week](https://img.shields.io/npm/dw/mynewcli.svg)](https://npmjs.org/package/mynewcli)

<!-- toc -->
* [starkit](#starkit)
* [Usage](#usage)
* [Commands](#commands)
<!-- tocstop -->

# Usage

<!-- usage -->
```sh-session
$ npm install -g starkit
$ starkit COMMAND
running command...
$ starkit (--version)
starkit/1.0.1 linux-x64 node-v23.5.0
$ starkit --help [COMMAND]
USAGE
  $ starkit COMMAND
...
```
<!-- usagestop -->

# Commands

<!-- commands -->
* [`starkit help [COMMAND]`](#starkit-help-command)
* [`starkit update [CHANNEL]`](#starkit-update-channel)

## `starkit help [COMMAND]`

Display help for starkit.

```
USAGE
  $ starkit help [COMMAND...] [-n]

ARGUMENTS
  COMMAND...  Command to show help for.

FLAGS
  -n, --nested-commands  Include all nested commands in the output.

DESCRIPTION
  Display help for starkit.
```

_See code: [@oclif/plugin-help](https://github.com/oclif/plugin-help/blob/v6.2.20/src/commands/help.ts)_

## `starkit update [CHANNEL]`

update the starkit CLI

```
USAGE
  $ starkit update [CHANNEL] [--force |  | [-a | -v <value> | -i]] [-b ]

FLAGS
  -a, --available        See available versions.
  -b, --verbose          Show more details about the available versions.
  -i, --interactive      Interactively select version to install. This is ignored if a channel is provided.
  -v, --version=<value>  Install a specific version.
      --force            Force a re-download of the requested version.

DESCRIPTION
  update the starkit CLI

EXAMPLES
  Update to the stable channel:

    $ starkit update stable

  Update to a specific version:

    $ starkit update --version 1.0.0

  Interactively select version:

    $ starkit update --interactive

  See available versions:

    $ starkit update --available
```

_See code: [@oclif/plugin-update](https://github.com/oclif/plugin-update/blob/v4.6.21/src/commands/update.ts)_
<!-- commandsstop -->
