# auxin
Developer (and bot) friendly wrapper around the Signal protocol (https://signal.org)

In order to use this application, you should have a "state" directory inside your working directory. This "state" directory should have a state/avatars and state/data. If you already have a signal-cli instance set up, this will (by default) be your ~/.local/share/signal-cli directory. You can create a symlink directly to this directory and it'll work fine. Under Linux, just use ``ln -s $HOME/.local/share/signal-cli state`` while you are inside auxin's working directory (most likely your `auxin` directory).
