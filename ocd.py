from binaryninja import *


class OcdView(BinaryView):

    name = "OCD"


    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)


    @classmethod
    def is_valid_for_data(self, data):
        log_info("sssssssssssssssssssssssssssss")
        log_info(data[:3])
        log_info(data[18:20])
        log_info("sssssssssssssssssssssssssssss")
        if data[:4] == b'\x7fELF' and data[18:20] == b'\x3e\x00':
            return True
        return False


    def on_complete(self):
        for i in range(0x10):
            log_info("complete")


    def init(self):
        log_info("sssssssssssssssssssssssssssss")
        log_info("init() called")
        log_info("sssssssssssssssssssssssssssss")

        AnalysisCompletionEvent(self, self.on_complete)
        return True

OcdView.register()
