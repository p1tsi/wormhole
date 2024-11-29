import time
import frida

from wormhole import Core

"""
NB: to run this script, it is necessary to have previously launched in a shell the command 'iproxy'
"""

if __name__ == "__main__":
    c = Core(
        frida.get_usb_device(),
        "com.apple.Preferences",
        None
    )

    if c.run():
        c.resume_target()
        c.execute_method("dumpipa", None)

        while True:
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                print("\nCtrl + C detected. Exiting the program...")
                break
