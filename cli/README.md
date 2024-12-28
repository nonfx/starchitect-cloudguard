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
starchitect-cloudguard/0.0.0 darwin-arm64 node-v23.5.0
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
* [`starchitect-cloudguard plugins`](#starchitect-cloudguard-plugins)
* [`starchitect-cloudguard plugins add PLUGIN`](#starchitect-cloudguard-plugins-add-plugin)
* [`starchitect-cloudguard plugins:inspect PLUGIN...`](#starchitect-cloudguard-pluginsinspect-plugin)
* [`starchitect-cloudguard plugins install PLUGIN`](#starchitect-cloudguard-plugins-install-plugin)
* [`starchitect-cloudguard plugins link PATH`](#starchitect-cloudguard-plugins-link-path)
* [`starchitect-cloudguard plugins remove [PLUGIN]`](#starchitect-cloudguard-plugins-remove-plugin)
* [`starchitect-cloudguard plugins reset`](#starchitect-cloudguard-plugins-reset)
* [`starchitect-cloudguard plugins uninstall [PLUGIN]`](#starchitect-cloudguard-plugins-uninstall-plugin)
* [`starchitect-cloudguard plugins unlink [PLUGIN]`](#starchitect-cloudguard-plugins-unlink-plugin)
* [`starchitect-cloudguard plugins update`](#starchitect-cloudguard-plugins-update)
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

## `starchitect-cloudguard plugins`

List installed plugins.

```
USAGE
  $ starchitect-cloudguard plugins [--json] [--core]

FLAGS
  --core  Show core plugins.

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  List installed plugins.

EXAMPLES
  $ starchitect-cloudguard plugins
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/index.ts)_

## `starchitect-cloudguard plugins add PLUGIN`

Installs a plugin into starchitect-cloudguard.

```
USAGE
  $ starchitect-cloudguard plugins add PLUGIN... [--json] [-f] [-h] [-s | -v]

ARGUMENTS
  PLUGIN...  Plugin to install.

FLAGS
  -f, --force    Force npm to fetch remote resources even if a local copy exists on disk.
  -h, --help     Show CLI help.
  -s, --silent   Silences npm output.
  -v, --verbose  Show verbose npm output.

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  Installs a plugin into starchitect-cloudguard.

  Uses npm to install plugins.

  Installation of a user-installed plugin will override a core plugin.

  Use the STARCHITECT_CLOUDGUARD_NPM_LOG_LEVEL environment variable to set the npm loglevel.
  Use the STARCHITECT_CLOUDGUARD_NPM_REGISTRY environment variable to set the npm registry.

ALIASES
  $ starchitect-cloudguard plugins add

EXAMPLES
  Install a plugin from npm registry.

    $ starchitect-cloudguard plugins add myplugin

  Install a plugin from a github url.

    $ starchitect-cloudguard plugins add https://github.com/someuser/someplugin

  Install a plugin from a github slug.

    $ starchitect-cloudguard plugins add someuser/someplugin
```

## `starchitect-cloudguard plugins:inspect PLUGIN...`

Displays installation properties of a plugin.

```
USAGE
  $ starchitect-cloudguard plugins inspect PLUGIN...

ARGUMENTS
  PLUGIN...  [default: .] Plugin to inspect.

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  Displays installation properties of a plugin.

EXAMPLES
  $ starchitect-cloudguard plugins inspect myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/inspect.ts)_

## `starchitect-cloudguard plugins install PLUGIN`

Installs a plugin into starchitect-cloudguard.

```
USAGE
  $ starchitect-cloudguard plugins install PLUGIN... [--json] [-f] [-h] [-s | -v]

ARGUMENTS
  PLUGIN...  Plugin to install.

FLAGS
  -f, --force    Force npm to fetch remote resources even if a local copy exists on disk.
  -h, --help     Show CLI help.
  -s, --silent   Silences npm output.
  -v, --verbose  Show verbose npm output.

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  Installs a plugin into starchitect-cloudguard.

  Uses npm to install plugins.

  Installation of a user-installed plugin will override a core plugin.

  Use the STARCHITECT_CLOUDGUARD_NPM_LOG_LEVEL environment variable to set the npm loglevel.
  Use the STARCHITECT_CLOUDGUARD_NPM_REGISTRY environment variable to set the npm registry.

ALIASES
  $ starchitect-cloudguard plugins add

EXAMPLES
  Install a plugin from npm registry.

    $ starchitect-cloudguard plugins install myplugin

  Install a plugin from a github url.

    $ starchitect-cloudguard plugins install https://github.com/someuser/someplugin

  Install a plugin from a github slug.

    $ starchitect-cloudguard plugins install someuser/someplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/install.ts)_

## `starchitect-cloudguard plugins link PATH`

Links a plugin into the CLI for development.

```
USAGE
  $ starchitect-cloudguard plugins link PATH [-h] [--install] [-v]

ARGUMENTS
  PATH  [default: .] path to plugin

FLAGS
  -h, --help          Show CLI help.
  -v, --verbose
      --[no-]install  Install dependencies after linking the plugin.

DESCRIPTION
  Links a plugin into the CLI for development.

  Installation of a linked plugin will override a user-installed or core plugin.

  e.g. If you have a user-installed or core plugin that has a 'hello' command, installing a linked plugin with a 'hello'
  command will override the user-installed or core plugin implementation. This is useful for development work.


EXAMPLES
  $ starchitect-cloudguard plugins link myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/link.ts)_

## `starchitect-cloudguard plugins remove [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ starchitect-cloudguard plugins remove [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ starchitect-cloudguard plugins unlink
  $ starchitect-cloudguard plugins remove

EXAMPLES
  $ starchitect-cloudguard plugins remove myplugin
```

## `starchitect-cloudguard plugins reset`

Remove all user-installed and linked plugins.

```
USAGE
  $ starchitect-cloudguard plugins reset [--hard] [--reinstall]

FLAGS
  --hard       Delete node_modules and package manager related files in addition to uninstalling plugins.
  --reinstall  Reinstall all plugins after uninstalling.
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/reset.ts)_

## `starchitect-cloudguard plugins uninstall [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ starchitect-cloudguard plugins uninstall [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ starchitect-cloudguard plugins unlink
  $ starchitect-cloudguard plugins remove

EXAMPLES
  $ starchitect-cloudguard plugins uninstall myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/uninstall.ts)_

## `starchitect-cloudguard plugins unlink [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ starchitect-cloudguard plugins unlink [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ starchitect-cloudguard plugins unlink
  $ starchitect-cloudguard plugins remove

EXAMPLES
  $ starchitect-cloudguard plugins unlink myplugin
```

## `starchitect-cloudguard plugins update`

Update installed plugins.

```
USAGE
  $ starchitect-cloudguard plugins update [-h] [-v]

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Update installed plugins.
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/update.ts)_

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
