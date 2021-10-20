# auxin
Developer (and bot) friendly wrapper around the Signal protocol (https://signal.org)

## Try it out!

Auxin's `echobot` is now running! Try it out at +12406171615! Any text message sent to this bot will be resent to the original sender.

This instance is running on https://fly.io/ in the IAD region.

`echobot/init.sh` serves to bootstrap the SignalApp keystate onto a fly persistent volume attached to `auxin-echobot`.

See fly.toml for details, ie)

```
[[mounts]]
  source = "auxin_echobot_state"
  destination = "/auxin_state"
```

## Running Auxin-cli

### Configuration
In order to use this application, *currently*, you must first set up a user account via signal-cli. Auxin is fully compatible with the protocol state store used by signal-cli. By default, auxin will look for this information under the path ``./state/data``, however you can specify the directory used with the ``--config`` command-line option. To get up and running quickly if you already have the files present for a Signal user account set up on your computer, under Linux, just use ``ln -s $HOME/.local/share/signal-cli state`` while you are inside auxin's working directory (most likely your `auxin` directory).

### User ID
One required command-line argument for auxin-cli is the ``user`` parameter. Use either your Signal account UUID or the phone number associated with this account (in E164 format, i.e. ``+[country code][phone number]``).

### Commands
Currently, Auxin has a ``send`` command, which sends a Signal message to the recipient of your choosing, a ``receive`` command, which polls Signal's web API for new messages intended for this account, an ``upload`` command, which uploads an attachment to Signal's CDN and prints the resulting attachment pointer, and an ``echoserver`` command, for testing. There is also a ``repl`` command, for debugging and testing in development, and an experimental ``getpayaddress`` command, which is a work in progress.

Last, but not least, there is a `help` command. Type ``auxin-cli -h`` or ``auxin-cli help`` for more information on how to use this program in general, or ``auxin-cli [COMMAND] -h`` for more information on how to use a specific command.

## Project Structure

### Crates
Auxin is split into three crates:
* **auxin_protos**, which is used to generate rust code from protocol buffers automatically.
* **auxin**, which contains the Signal protocol logic. This is the main bulk of the project, but it doesn't *directly* perform any i/o (on the network or on the filesystem) and isn't opinionated on how you execute its asynchronous Rust functions and methods. The idea is that a comparatively-minimal amount of code would need to be written to run Auxin in a different environment (such as webassembly for example). All you need is to implement the ``AuxinNetManager`` and ``AuxinStateManager`` traits and, using instances of your implementations of those traits, construct an AuxinApp instance.
* **auxin_cli**, a command-line tool which is our first and primary implementation of an auxin frontent. This implements the ``AuxinNetManager`` and ``AuxinStateManager`` traits mentioned above. auxin_cli is intended to be compatible with signal_cli's protocol store.
