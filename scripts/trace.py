import time
import frida

from wormhole import Core

if __name__ == "__main__":
    c = Core(
        frida.get_usb_device(),
        "com.apple.Preferences",
        None
    )

    if c.run():
        c.resume_target()
        c.operations(["xpc"], [], ["stdout"])

        while True:
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                print("\nCtrl + C detected. Exiting the program...")
                break
