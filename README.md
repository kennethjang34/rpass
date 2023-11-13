# rpass

A rust password manager forked from cortex/ripasso

Password store paths can be added to the config file `~/.config/rpass/settings.toml` like following:

```

[stores."a@gmail.com"]
path = "/Users/JANG/.password-store/a@gmail.com"
pgp_implementation = "gpg"

[stores."b@gmail.com"]
path = "/Users/JANG/.password-store/b@gmail.com"
pgp_implementation = "gpg"

```

In order to add a new user to the password store,
create a new store dir with .gpg-id file and add the dir path to `~/.config/rpass/settings.toml` like following:

### ex

`echo "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD" >> ~/.password-store/someuser@gmail.com/.gpg-id` or `echo "a@gmail.com" >> ~/.password-store/someuser@gmail.com/.gpg-id`, followed by
`echo "/Users/JANG/.password-store/someuser@gmail.com" >> ~/.config/rpass/settings.toml`

In addition to .gpg-id file, add the fingerpirnt to `~/.gitconfig` or make the user dir a git repo and add the fingerprint to the git config of the repo.

### ex

`echo "[user]\nsigningkey=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD" >> ~/.password-store/someuser@gmailc.com/.git/config`

To sign commits, add your GPG key fingerprint to `~/.gitconfig` with key `user.signingkey` like following:

```

[user]
name = yourname
email = youremail@gmail.com
signingkey = ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD

```

or

```
[user]
name = yourname
email = youremail@gmail.com
signingkey = youremail@gmail.com
```
