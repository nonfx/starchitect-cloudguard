# mynewcli

Testing 123

[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![Version](https://img.shields.io/npm/v/mynewcli.svg)](https://npmjs.org/package/mynewcli)
[![Downloads/week](https://img.shields.io/npm/dw/mynewcli.svg)](https://npmjs.org/package/mynewcli)

<!-- toc -->

- [Usage](#usage)
- [Commands](#commands)
<!-- tocstop -->

# Usage

<!-- usage -->

```sh-session
$ npm install -g mynewcli
$ mynewcli COMMAND
running command...
$ mynewcli (--version)
mynewcli/0.0.0 darwin-arm64 node-v20.16.0
$ mynewcli --help [COMMAND]
USAGE
  $ mynewcli COMMAND
...
```

<!-- usagestop -->

# Commands

<!-- commands -->

- [`mynewcli hello PERSON`](#mynewcli-hello-person)
- [`mynewcli hello world`](#mynewcli-hello-world)
- [`mynewcli help [COMMAND]`](#mynewcli-help-command)
- [`mynewcli plugins`](#mynewcli-plugins)
- [`mynewcli plugins add PLUGIN`](#mynewcli-plugins-add-plugin)
- [`mynewcli plugins:inspect PLUGIN...`](#mynewcli-pluginsinspect-plugin)
- [`mynewcli plugins install PLUGIN`](#mynewcli-plugins-install-plugin)
- [`mynewcli plugins link PATH`](#mynewcli-plugins-link-path)
- [`mynewcli plugins remove [PLUGIN]`](#mynewcli-plugins-remove-plugin)
- [`mynewcli plugins reset`](#mynewcli-plugins-reset)
- [`mynewcli plugins uninstall [PLUGIN]`](#mynewcli-plugins-uninstall-plugin)
- [`mynewcli plugins unlink [PLUGIN]`](#mynewcli-plugins-unlink-plugin)
- [`mynewcli plugins update`](#mynewcli-plugins-update)

## `mynewcli hello PERSON`

Say hello

```
USAGE
  $ mynewcli hello PERSON -f <value>

ARGUMENTS
  PERSON  Person to say hello to

FLAGS
  -f, --from=<value>  (required) Who is saying hello

DESCRIPTION
  Say hello

EXAMPLES
  $ mynewcli hello friend --from oclif
  hello friend from oclif! (./src/commands/hello/index.ts)
```

_See code: [src/commands/hello/index.ts](https://github.com/nonfx/starchitect-cloudguard/blob/v0.0.0/src/commands/hello/index.ts)_

## `mynewcli hello world`

Say hello world

```
USAGE
  $ mynewcli hello world

DESCRIPTION
  Say hello world

EXAMPLES
  $ mynewcli hello world
  hello world! (./src/commands/hello/world.ts)
```

_See code: [src/commands/hello/world.ts](https://github.com/nonfx/starchitect-cloudguard/blob/v0.0.0/src/commands/hello/world.ts)_

## `mynewcli help [COMMAND]`

Display help for mynewcli.

```
USAGE
  $ mynewcli help [COMMAND...] [-n]

ARGUMENTS
  COMMAND...  Command to show help for.

FLAGS
  -n, --nested-commands  Include all nested commands in the output.

DESCRIPTION
  Display help for mynewcli.
```

_See code: [@oclif/plugin-help](https://github.com/oclif/plugin-help/blob/v6.2.20/src/commands/help.ts)_

## `mynewcli plugins`

List installed plugins.

```
USAGE
  $ mynewcli plugins [--json] [--core]

FLAGS
  --core  Show core plugins.

GLOBAL FLAGS
  --json  Format output as json.

DESCRIPTION
  List installed plugins.

EXAMPLES
  $ mynewcli plugins
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/index.ts)_

## `mynewcli plugins add PLUGIN`

Installs a plugin into mynewcli.

```
USAGE
  $ mynewcli plugins add PLUGIN... [--json] [-f] [-h] [-s | -v]

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
  Installs a plugin into mynewcli.

  Uses npm to install plugins.

  Installation of a user-installed plugin will override a core plugin.

  Use the MYNEWCLI_NPM_LOG_LEVEL environment variable to set the npm loglevel.
  Use the MYNEWCLI_NPM_REGISTRY environment variable to set the npm registry.

ALIASES
  $ mynewcli plugins add

EXAMPLES
  Install a plugin from npm registry.

    $ mynewcli plugins add myplugin

  Install a plugin from a github url.

    $ mynewcli plugins add https://github.com/someuser/someplugin

  Install a plugin from a github slug.

    $ mynewcli plugins add someuser/someplugin
```

## `mynewcli plugins:inspect PLUGIN...`

Displays installation properties of a plugin.

```
USAGE
  $ mynewcli plugins inspect PLUGIN...

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
  $ mynewcli plugins inspect myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/inspect.ts)_

## `mynewcli plugins install PLUGIN`

Installs a plugin into mynewcli.

```
USAGE
  $ mynewcli plugins install PLUGIN... [--json] [-f] [-h] [-s | -v]

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
  Installs a plugin into mynewcli.

  Uses npm to install plugins.

  Installation of a user-installed plugin will override a core plugin.

  Use the MYNEWCLI_NPM_LOG_LEVEL environment variable to set the npm loglevel.
  Use the MYNEWCLI_NPM_REGISTRY environment variable to set the npm registry.

ALIASES
  $ mynewcli plugins add

EXAMPLES
  Install a plugin from npm registry.

    $ mynewcli plugins install myplugin

  Install a plugin from a github url.

    $ mynewcli plugins install https://github.com/someuser/someplugin

  Install a plugin from a github slug.

    $ mynewcli plugins install someuser/someplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/install.ts)_

## `mynewcli plugins link PATH`

Links a plugin into the CLI for development.

```
USAGE
  $ mynewcli plugins link PATH [-h] [--install] [-v]

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
  $ mynewcli plugins link myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/link.ts)_

## `mynewcli plugins remove [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ mynewcli plugins remove [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ mynewcli plugins unlink
  $ mynewcli plugins remove

EXAMPLES
  $ mynewcli plugins remove myplugin
```

## `mynewcli plugins reset`

Remove all user-installed and linked plugins.

```
USAGE
  $ mynewcli plugins reset [--hard] [--reinstall]

FLAGS
  --hard       Delete node_modules and package manager related files in addition to uninstalling plugins.
  --reinstall  Reinstall all plugins after uninstalling.
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/reset.ts)_

## `mynewcli plugins uninstall [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ mynewcli plugins uninstall [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ mynewcli plugins unlink
  $ mynewcli plugins remove

EXAMPLES
  $ mynewcli plugins uninstall myplugin
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/uninstall.ts)_

## `mynewcli plugins unlink [PLUGIN]`

Removes a plugin from the CLI.

```
USAGE
  $ mynewcli plugins unlink [PLUGIN...] [-h] [-v]

ARGUMENTS
  PLUGIN...  plugin to uninstall

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Removes a plugin from the CLI.

ALIASES
  $ mynewcli plugins unlink
  $ mynewcli plugins remove

EXAMPLES
  $ mynewcli plugins unlink myplugin
```

## `mynewcli plugins update`

Update installed plugins.

```
USAGE
  $ mynewcli plugins update [-h] [-v]

FLAGS
  -h, --help     Show CLI help.
  -v, --verbose

DESCRIPTION
  Update installed plugins.
```

_See code: [@oclif/plugin-plugins](https://github.com/oclif/plugin-plugins/blob/v5.4.23/src/commands/plugins/update.ts)_

<!-- commandsstop -->
