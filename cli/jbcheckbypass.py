from cli.base import BaseModule


class JBCheckBypass(BaseModule):
    
    def __init__(self, wh):
        super().__init__(wh, JBCheckBypass.__name__.lower())

    def _run(self):
        data, _ = self.wh.execute_method(self.command)
        if data:
            print("JB detection bypassed: ✅")
        else:
            print("Error trying bypass jb detection")