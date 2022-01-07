# auxin

Developer (and bot) friendly wrapper around the Signal protocol (<https://signal.org>)

## Try it out!

Auxin's `echobot` is now running! Try it out at +12406171615! Any text message sent to this bot will be resent to the original sender.

This instance is running on <https://fly.io/> in the IAD region.

`echobot/init.sh` serves to bootstrap the SignalApp keystate onto a fly persistent volume attached to `auxin-echobot`.

It then launches `auxin` like

 > /app/auxin_cli --config $auxin_state --user +$echobot echoserver | jq -c

See `init.sh` and `fly.toml` for more details.`

## Running Auxin-cli

### Configuration and Running Locally

In order to use this application, *currently*, you must first set up a user account via signal-cli. Auxin is fully compatible with the protocol state store used by signal-cli. By default, auxin will look for this information under the path ``./state/data``, however you can specify the directory used with the ``--config`` command-line option. To get up and running quickly if you already have the files present for a Signal user account set up on your computer, under Linux, just use ``ln -s $HOME/.local/share/signal-cli state`` while you are inside auxin's working directory (most likely your `auxin` directory).

You'll need a working rust enviornment on your system to build Auxin. [Install rust here.](https://www.rust-lang.org/learn/get-started) Then, after you've gotten rust nightly set up with ``rustup default nightly``, ```cargo build``` will get you started. The auxin-cli binary will be in ```/auxin/target/debug/```.

You should now be ready to start hacking on Auxin! Start the echoserver with: \
```./auxin-cli --config [SIGNAL CLI DIRECTORY] --user +12232087156 echoserver```

### User ID

One required command-line argument for auxin-cli is the ``user`` parameter. Use either your Signal account UUID or the phone number associated with this account (in E164 format, i.e. ``+[country code][area code][phone number]``).

### Commands

``send`` sends a Signal message to the specified recipient.\
``receive`` and ``receiveLoop`` poll Signal's web API for new messages intended for the set account.\
``upload`` uploads an attachment to Signal's CDN and prints the resulting attachment pointer.\
``echoserver`` Demo for testing, sends back what it recieves.\
``repl`` for debugging and testing in development.\
``getpayaddress`` Experimental command to get the MobileCoin address of a specified user.\

Last, but not least, there is a `help` command. Type ``auxin-cli -h`` or ``auxin-cli help`` for more information on how to use this program in general, or ``auxin-cli [COMMAND] -h`` for more information on how to use a specific command.

### JsonRPC Interface
Auxin supports a JsonRPC mode wherein all commands can be invoked via a JsonRPC Repl accessed via the command line or file descriptors using another language like python. 

Example commands include:
#### Set profile
```
{"jsonrpc":"2.0","id":666,"method":"setProfile","params":{"name":{"givenName":"Thought","familyName":"Criminal"},"about":"I encrypt my thoughts with math","avatarFile":"profile.png","mobilecoinAddress":"[b64 encoded mobilecoin address]"}}
```

#### Send Message
```
{"jsonrpc":"2.0","id":666,"method":"send","params":{"destination":"+15555555555","message":"But do you REALLY know about turtles?","attachments":["turtles.png","also_turtles.jpeg"]}}
```

## Project Structure

### Crates

Auxin is split into three crates:

* **auxin_protos**, which is used to generate rust code from protocol buffers automatically.
* **auxin**, which contains the Signal protocol logic. This is the main bulk of the project, but it doesn't *directly* perform any i/o (on the network or on the filesystem) and isn't opinionated on how you execute its asynchronous Rust functions and methods. The idea is that a comparatively-minimal amount of code would need to be written to run Auxin in a different environment (such as webassembly for example). All you need is to implement the ``AuxinNetManager`` and ``AuxinStateManager`` traits and, using instances of your implementations of those traits, construct an AuxinApp instance.
* **auxin_cli**, a command-line tool which is our first and primary implementation of an auxin frontend. This implements the ``AuxinNetManager`` and ``AuxinStateManager`` traits mentioned above. auxin_cli is intended to be compatible with signal_cli's protocol store.
