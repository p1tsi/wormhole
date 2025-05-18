import os
import json
import struct
import base64
import importlib

import frida
import flask

from flask_socketio import SocketIO, Namespace

from wormhole import Core

app = flask.Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # , logger=True, engineio_logger=True)


@app.route("/api/devices", methods=['GET'])
def get_devices():
    """
    Get devices
    """
    devices_list = list()
    for device in frida.enumerate_devices():  # list(filter(lambda d: d.type == 'usb' or d.type == 'local', frida.enumerate_devices())):
        if device.id == "socket" or device.id == "barebone":
            continue
        device_info = dict({"name": device.name, "id": device.id, "type": device.type})
        devices_list.append(device_info)

    output = {
        "server": {
            "name": "Flask",
            "version": importlib.metadata.version("flask"),
            "ip": "127.0.0.1"
        },
        "version": importlib.metadata.version("frida"),
        "list": devices_list
    }

    return flask.Response(json.dumps(output))


@app.route('/api/device/<device_id>', methods=['DELETE'])
def remove_device(device_id: str):
    """
    Remove device from list
    :device_id: the name of the device to be removed.
    """
    frida.get_device_manager().remove_remote_device(device_id)
    return flask.Response(json.dumps({'status': 'ok'}))


@app.route('/api/device/<device_id>/info', methods=['GET'])
def get_system_info(device_id: str):
    """
    Retrieve device info by id
    :device_id: id for device. For example, "local", or phone udid
    """
    device = frida.get_device(device_id)
    return flask.Response(json.dumps(device.query_system_parameters()))


@app.route('/api/device/<device_id>/apps', methods=['GET'])
def get_installed_apps(device_id:str):
    """
    Retrieve all applications installed and all processes running on the device
    :device_id: id for device. For example, "local", or phone udid
    """
    device = frida.get_device(device_id)

    installed_apps = list()
    for application in device.enumerate_applications(scope="full"):
        app_info = dict({"name": application.name,
                         "identifier": application.identifier,
                         "icon": f"data:image/png;base64,"
                                 f"{base64.b64encode(application.parameters.get('icons')[0].get('image')).decode()}"
                         })
        installed_apps.append(app_info)

    running_processes = list()

    for process in device.enumerate_processes(scope="metadata"):
        process_info = {
            "pid": process.pid,
            'name': process.name,
        }
        if process.parameters.get('icons', None):
            process_info['icon'] = (f"data:image/png;base64,"
                                    f"{base64.b64encode(process.parameters.get('icons')[-1].get('image')).decode()}")
        running_processes.append(process_info)

    installed_apps = {
        "apps": installed_apps,
        "processes": running_processes
    }

    return flask.Response(json.dumps(installed_apps))


@app.route('/api/remote/add', methods=['PUT'])
def add_remote_device():
    """
    Add a remote device by host:port
    """
    host = flask.request.json.get('host')
    # TODO: check if the remote device is reachable
    remote_device = frida.get_device_manager().add_remote_device(host)
    return flask.Response(json.dumps({'status': 'ok', 'id': remote_device.id}))


@app.route('/api/r2/<bundle_id>', methods=['GET'])
def get_bundle_binaries(bundle_id):
    def is_macho(file_path):
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                return False

            magic = struct.unpack('<I', magic_bytes)[0]

        macho_magic_numbers = {0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE}

        return magic in macho_magic_numbers

    bundle_path = os.path.join('appData', f'{bundle_id}',
                               'Payload')
    subdir = os.listdir(bundle_path)[0]
    macho_files = list()
    for file in os.listdir(os.path.join(bundle_path, subdir)):
        filepath = os.path.join(bundle_path, subdir, file)
        if file == "Frameworks":
            for framework in os.listdir(filepath):
                if ".framework" in framework:
                    macho_files.append(
                        os.path.join(
                            filepath,
                            framework,
                            framework.replace(".framework", "")
                        )
                    )
        if os.path.isdir(filepath):
            continue
        if is_macho(filepath):
            macho_files.append(filepath)

    return macho_files


class SessionNamespace(Namespace):
    core = None

    def on_connect(self):
        print("Session connect")
        print(flask.request.args)

        if flask.request.args.get("device", None):
            is_app = True
            if flask.request.args.get("bundle").isnumeric():
                self.core = Core(
                    frida.get_device(flask.request.args.get("device")),
                    int(flask.request.args.get("bundle")),
                    self
                )
                is_app = False
            else:
                self.core = Core(
                    frida.get_device(flask.request.args.get("device")),
                    flask.request.args.get("bundle"),
                    self
                )

            res = self.core.run()

            if res:
                self.emit('ready')
            else:
                self.core = None

            self.emit('spawned', {'isApp': is_app, 'spawned': res})

    def on_disconnect(self):
        self.core.detach_session()

    def on_rpc(self, method, args):
        try:
            if method == 'operations':
                modules, custom_modules = args[0], args[1]
                was_resumed = self.core.is_target_resumed()
                # res = getattr(self.wormhole, method)(args[0], args[1], ["file"])  # , "websocket"
                res = self.core.operations(modules, custom_modules, ["file"])
                if res and not was_resumed:
                    self.emit('resumed')
                return {'status': 'ok', 'data': res}
            elif method == 'unhook':
                return {'status': 'ok', 'data': self.core.unhook()}
            elif method == 'resume':
                resumed = self.core.resume_target()
                if resumed:
                    self.emit('resumed')
                    return {'status': 'ok', 'data': resumed}

                return {'status': 'error', 'error': 'Error resuming app'}
            elif method == 'customplugins':
                return {'status': 'ok', 'data': self.core.custom_modules()}
            elif method == 'radare2':
                print("radare2")
            else:
                data, error = self.core.execute_method(method, *args)
                return {'status': 'error', 'error': error} if error else {'status': 'ok', 'data': data}
        except Exception as e:
            print(e)
            return {'status': 'error', 'error': str(e)}

    def on_kill(self):
        self.core.kill_session()


class DeviceNamespace(Namespace):
    def on_connect(self):
        print("CONNECTED /devices")

    def on_disconnect(self):
        print("DISCONNECTED /devices")

    def on_kill(self):
        print("KILLED /devices")


socketio.on_namespace(SessionNamespace('/session'))
socketio.on_namespace(DeviceNamespace('/devices'))

socketio.run(app, port=31337, allow_unsafe_werkzeug=True)  # , debug=True)
