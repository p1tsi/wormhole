import frida
import questionary

from InquirerPy import inquirer

from wormhole import Core
from cli.checksec import Checksec
from cli.info import Info
from cli.keychain import Keychain
from cli.fd import FileDescriptor
from cli.url import Url
from cli.classdump import Classdump
from cli.heap import Heap
from cli.hook import Hook
from cli.dumpipa import Dumpipa
from cli.certpinning import Certpinning
from cli.jbcheckbypass import JBCheckBypass
from cli.fs import FileSystem
from cli.symbol import Symbol


EARLY_OPERATIONS = {
    "resume": None,
    "hook": Hook,
    "certpinning": Certpinning,
    "jbcheckbypass": JBCheckBypass
}

OPERATIONS = {
    "info": Info,
    "checksec": Checksec,
    "keychain": Keychain,
    "fileDes": FileDescriptor,
    "url": Url,
    "classdump": Classdump,
    "heap": Heap,
    "dumpipa": Dumpipa,
    "fs": FileSystem,
    "symbol": Symbol,
    "exit": None
}


def print_asciiart():

    ascii_art = r"""
 __        __                   _           _      
 \ \      / /__  _ __ _ __ ___ | |__   ___ | | ___ 
  \ \ /\ / / _ \| '__| '_ ` _ \| '_ \ / _ \| |/ _ \
   \ V  V / (_) | |  | | | | | | | | | (_) | |  __/
    \_/\_/ \___/|_|  |_| |_| |_|_| |_|\___/|_|\___|

                                            by p1tsi
"""

    print(ascii_art)


def print_intro_message():
    intro_message = "Welcome to Wormhole!\n"
    intro_message += "I'll try to help you finding all 🐛 inside 🍎 applications or processes!\n"
    intro_message += "\t\t\t      ...and maybe 🤖 in the future...\n"
    print(intro_message)

def print_environment():
    print(f"Frida: {frida.__version__}\n")

def get_available_devices():
    devices, device_list = [], []
    for d in frida.enumerate_devices():
        if d.id != "socket" and d.id != "barebone" and d.id != "local":
            device_list.append(f"{d.id} ({d.name})")
            devices.append(d)
    return devices, device_list

def add_remote_device():
    frida.get_device_manager().add_remote_device("192.168.64.3")

def choose_device():
    devices, device_list = get_available_devices()
    print(devices)

    device_list.append("add")
    choice = questionary.select(
        "Here are the available devices:", choices=device_list
    ).ask()

    if choice == "add":
        add_remote_device()
        return choose_device()

    idx = device_list.index(choice)
    return devices[idx]

def choose_app_or_process():
    choice = questionary.select(
        "What would you like to inspect?", choices=["Apps", "Processes"]
    ).ask()

    return choice

def list_apps(device):
    apps_objects, apps = [], []
    try:
        apps_objects = sorted(device.enumerate_applications(), key=lambda app: app.name)
        apps = [f"• {app.name} ({app.identifier})" for app in apps_objects]
    except Exception as e:
        print(f"Could not list applications: {e}")

    return apps_objects, apps
    

def list_processes(device):
    processes_objects, processes = [], []
    try:
        processes_objects = sorted(device.enumerate_processes(), key=lambda p: p.pid, reverse=True)
        processes = [f"• {p.name} ({p.pid})" for p in processes_objects]
    except Exception as e:
        print(f"Could not list applications: {e}")

    return processes_objects, processes


def choose_app_or_proc(device, app_or_proc="Apps"):
    instances, instance_list = list_apps(device) if app_or_proc == "Apps" else list_processes(device)
    message = "Select an app:" if app_or_proc == "Apps" else "Select a process:"
    choice = inquirer.fuzzy(
        message=message, 
        choices=instance_list,
        max_height="90%"
    ).execute()

    if not choice:
        return None

    idx = instance_list.index(choice)
    return instances[idx].identifier if app_or_proc == "Apps" else instances[idx].pid



if __name__ == "__main__":

    print_asciiart()
    print_intro_message()
    print_environment()

    # Choose device
    device = choose_device()

    not_choosen = True
    while not_choosen:
        # Choose if analayze app or process
        apps_or_processes = choose_app_or_process()

        # Choose the app or the process
        instance = choose_app_or_proc(device, apps_or_processes)        

        if instance:
            not_choosen = False


    # Attach the agent and start the analysis
    core = Core(device, instance, None)
    started = core.run()

    #if started:
    #    core.resume_target()

    resumed = apps_or_processes == "Processes"

    while True:

        if not resumed:
            print("‼️  TARGET NEED TO BE RESUMED ‼️")
            print("Select 'resume' or start hooking to resume the app")
            operations = EARLY_OPERATIONS
        
        else:
            operations = EARLY_OPERATIONS | OPERATIONS

        try:
            choice = inquirer.fuzzy(
                message="Available operations:", 
                choices=operations
            ).execute()

            if choice == "exit":
                core.kill_session()
                exit(0)
            
            if started and choice == "resume":
                core.resume_target()
                resumed = True
            else:
                try:
                    operations.get(choice)(core).run()

                    if choice == "hook":
                        resumed = True
                        
                except Exception as e:
                    print(f"Error in {choice} command: {e}")
                
                print()
                print("-" * 50)
        except KeyboardInterrupt:
            print("Goodbye!")
            core.kill_session()
            exit(0)
          