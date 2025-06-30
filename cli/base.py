class BaseModule:

    def __init__(self, wh, command):
        self.wh = wh
        self.command = command
    
    def _run(self):
        raise NotImplementedError()

    def run(self):
        try:
            self._run()
        except KeyboardInterrupt:
            return