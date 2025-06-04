import os
import frida
import questionary

from InquirerPy import inquirer

from wormhole import Core


OPERATIONS = [
    "checksec",
    "classdump",
    "heap/inspect",
    "exit"
]



def print_header():

    ascii_art = r"""
 __        __                   _           _      
 \ \      / /__  _ __ _ __ ___ | |__   ___ | | ___ 
  \ \ /\ / / _ \| '__| '_ ` _ \| '_ \ / _ \| |/ _ \
   \ V  V / (_) | |  | | | | | | | | | (_) | |  __/
    \_/\_/ \___/|_|  |_| |_| |_|_| |_|\___/|_|\___|

                            with ❤️  by p1tsi \n
"""

    print(ascii_art)


def print_intro_message():
    intro_message = "Welcome to Wormhole! "
    intro_message += "I'll try to help you finding all 🐛 inside 🍎 applications or processes!"
    intro_message += "\n\n"
    print(intro_message)


def get_available_devices():
    devices, device_list = [], []
    for d in frida.enumerate_devices():
        if d.id != "socket" and d.id != "barebone" and d.id != "local":
            device_list.append(f"{d.id} ({d.name})")
            devices.append(d)
    return devices, device_list

def choose_device():
    devices, device_list = get_available_devices()

    if not devices:
        print("No devices found.")
        exit(1)

    choice = questionary.select(
        "Here are the available devices:", choices=device_list
    ).ask()

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

    idx = instance_list.index(choice)
    return instances[idx].identifier if app_or_proc == "Apps" else instances[idx].pid



if __name__ == "__main__":

    print_header()
    print_intro_message()

    # Choose device
    device = choose_device()

    # Choose if analayze app or process
    apps_or_processes = choose_app_or_process()

    # Choose the app or the process
    instance = choose_app_or_proc(device, apps_or_processes)

    # Attach the agent and start the analysis
    core = Core(device, instance, None)
    started = core.run()

    if started:
        core.resume_target()

    run = True
    while run:
        choice = inquirer.fuzzy(
            message="Available operations:", 
            choices=OPERATIONS
        ).execute()

        if choice == 'exit':
            core.kill_session()
            exit(0)

        data, err = core.execute_method(choice, 'PreferencesAppController')
        print(data)

        

    