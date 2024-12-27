# mynewcli

Testing 123

[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![Version](https://img.shields.io/npm/v/mynewcli.svg)](https://npmjs.org/package/mynewcli)
[![Downloads/week](https://img.shields.io/npm/dw/mynewcli.svg)](https://npmjs.org/package/mynewcli)

<!-- toc -->
* [mynewcli](#mynewcli)
* [Usage](#usage)
* [Commands](#commands)
<!-- tocstop -->

# Usage

<!-- usage -->
```sh-session
$ npm install -g starchitect-cloudguard
$ starchitect-cloudguard COMMAND
running command...
$ starchitect-cloudguard (--version)
starchitect-cloudguard/0.0.0 darwin-arm64 node-v22.6.0
$ starchitect-cloudguard --help [COMMAND]
USAGE
  $ starchitect-cloudguard COMMAND
...
```
<!-- usagestop -->

# Commands

<!-- commands -->
* [`starchitect-cloudguard help [COMMAND]`](#starchitect-cloudguard-help-command)
* [`starchitect-cloudguard iac test`](#starchitect-cloudguard-iac-test)
* [`starchitect-cloudguard runtime test`](#starchitect-cloudguard-runtime-test)

## `starchitect-cloudguard help [COMMAND]`

Display help for starchitect-cloudguard.

```
USAGE
  $ starchitect-cloudguard help [COMMAND...] [-n]

ARGUMENTS
  COMMAND...  Command to show help for.

FLAGS
  -n, --nested-commands  Include all nested commands in the output.

DESCRIPTION
  Display help for starchitect-cloudguard.
```

_See code: [@oclif/plugin-help](https://github.com/oclif/plugin-help/blob/v6.2.20/src/commands/help.ts)_

## `starchitect-cloudguard iac test`

Run security tests against Infrastructure as Code (coming soon)

```
USAGE
  $ starchitect-cloudguard iac test -p <value> -t terraform|cloudformation [--json] [--skip-install]

FLAGS
  -p, --path=<value>   (required) [default: .] Path to IAC code
  -t, --type=<option>  (required) [default: terraform] Type of IAC
                       <options: terraform|cloudformation>
      --skip-install   Skip installation of missing tools

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  Run security tests against Infrastructure as Code (coming soon)
```

_See code: [src/commands/iac/test.ts](https://github.com/nonfx/starchitect-cloudguard/blob/v0.0.0/src/commands/iac/test.ts)_

## `starchitect-cloudguard runtime test`

Run security tests against cloud runtime environments

```
USAGE
  $ starchitect-cloudguard runtime test [--json] [-c <value>] [-s <value>] [--profile <value>] [-r <value>]
    [--parallel] [--concurrency <value>] [--format json|stdout|html]

FLAGS
  -c, --cloud=<value>        Cloud provider to test
  -r, --region=<value>       Region to test
  -s, --service=<value>      Specific service to test
      --concurrency=<value>  [default: 5] Number of tests to run concurrently
      --format=<option>      [default: stdout] Output format
                             <options: json|stdout|html>
      --parallel             Run tests in parallel
      --profile=<value>      Cloud provider profile to use

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  Run security tests against cloud runtime environments
```

_See code: [src/commands/runtime/test.ts](https://github.com/nonfx/starchitect-cloudguard/blob/v0.0.0/src/commands/runtime/test.ts)_
<!-- commandsstop -->
