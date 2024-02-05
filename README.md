# Summary

Password manager with browser extension that helps users manage their secrets by public key cryptography.

# Core features

- Securely store user-ids, passwords, notes, associated domains(urls) in a user-selected 'store'
- A store coupub-keys/user-ids for encryption, which is useful in team environment
- Multiple password store support
- Stateful browser extension for currently available stores/passwords
- Auto-suggestion for user-id/password input fieldsld have multiple 

## Installation

Currently, only works on OSX and Linux, firefox and chrome (chromium users should be able to use them but would have to do extra configuration for native host. [Google has docs for it.](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)

### Required dependencies

- [Rust](https://www.rust-lang.org/tools/install)
- [wasm-pack](https://github.com/rustwasm/wasm-pack)
- [Trunk](https://trunkrs.dev/)
- GPG key that's capable of signing and encrypting. If you don't have GPG executables installed, take a look at [GPG official documentation](https://gnupg.org/documentation/index.html)
- Stand-alone launchable pin entry program like `pinentry-mac` on OSX

### Build script

Given you have the required dependencies available, you should be able to install through the provided build script. You can run `build.sh` included.
Default browser is set to Chrome. If you'd like to use firefox, add "-b firefox".


## Demo video(s)

### Installation
https://github.com/kennethjang34/browser-rpass/assets/89117160/1dbe4af7-cf63-4ed9-887b-aa4aa59687c7

### Basic Features

##### Create Store
https://github.com/kennethjang34/browser-rpass/assets/89117160/174d6fdd-29f5-467b-88cf-78ae45d131ed
##### Create Account
https://github.com/kennethjang34/browser-rpass/assets/89117160/250748f5-0391-4e9a-9bb5-61248df11918
##### Account Search
https://github.com/kennethjang34/browser-rpass/assets/89117160/8641272e-00dd-4b97-8edb-d8a50eaaf0f1
##### Edit Account
https://github.com/kennethjang34/browser-rpass/assets/89117160/e921dcbe-f0f4-447f-8900-4f75a9691f11
##### Delete Account
https://github.com/kennethjang34/browser-rpass/assets/89117160/49cc65cb-d010-4e25-afe7-e95977088bfe
##### Create Substore
https://github.com/kennethjang34/browser-rpass/assets/89117160/5e3ea81d-d18c-4635-af28-f2bbb1612a87
##### Table sorting based on current domain
https://github.com/kennethjang34/browser-rpass/assets/89117160/ca8e6183-264d-44e0-9048-7946c6201f50

### Data Syncing

##### Login status
https://github.com/kennethjang34/browser-rpass/assets/89117160/1df2cf2f-c5ab-4083-a0da-71852f12c70e
##### Create Account Syncing
https://github.com/kennethjang34/browser-rpass/assets/89117160/9d37b770-2672-4092-9d56-9ee85443b6ca
##### Edit Account Syncing
https://github.com/kennethjang34/browser-rpass/assets/89117160/d0840cc1-5c62-4b0d-908b-e40aef580d44
##### Delete Account Syncing
https://github.com/kennethjang34/browser-rpass/assets/89117160/223931bc-9543-4bda-bab4-328f5d817a93
##### Handle Multiple Stores
https://github.com/kennethjang34/browser-rpass/assets/89117160/499730cb-a749-4a8c-9569-7d24db932caa
