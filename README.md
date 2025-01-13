# Wormhole (WIP)

Wormhole is a [frida](https://github.com/frida) wrapper for iOS penetration tester and 
reverse engineers.

It lets you dynamically analyze iOS applications and 
extract as much information as possible in an easy way, without the need 
of knowing and launching several frida's commands.

### Capabilities:

- SSL Pinning bypass
- Jailbreak detection bypass
- Unencrypted IPA extraction
- Hooks by class of functions
- Customizable hooks
- IPA static information (entitlements, Info.plist...)
- Keychain dump
- Opened files descriptors (vnode and socket)
- Objective-C in-memory object dump
- ...


#### NB: this project is under (more or less) active development.
Some functionalities could not give precise and complete results
(for example, network or sqlite hooking modules).

### Architecture

The main componets of Wormhole are a GUI (TODO), wormhole-core,
which is the main controller of the system, and wormhole-agent, 
which is a JS frida agent injected inside processes 
to be explored.



### Usage
Build the project with `make`.

Run web server with `make run-web`.

Execute scripts with `make run-trace` or `make run-dump`.


## TODO

- Web GUI


### Credits

Certain parts of the wormhole-agent are taken from [here](https://github.com/ChiChou/grapefruit).
