"""Stream a single file to the model service without requests buffering it."""
import os
import uuid


class MultipartUpload:
    def __init__(self, handle):
        self.handle = handle
        self.boundary = uuid.uuid4().hex
        self.prefix = (f'--{self.boundary}\r\n'
                       'Content-Disposition: form-data; name="file"; filename="sample.exe"\r\n'
                       'Content-Type: application/octet-stream\r\n\r\n').encode('ascii')
        self.suffix = f'\r\n--{self.boundary}--\r\n'.encode('ascii')
        self.length = len(self.prefix) + os.fstat(handle.fileno()).st_size - handle.tell() + len(self.suffix)

    def __len__(self):
        return self.length

    @property
    def headers(self):
        return {'Content-Type': f'multipart/form-data; boundary={self.boundary}',
                'Content-Length': str(self.length)}

    def __iter__(self):
        yield self.prefix
        while chunk := self.handle.read(64 * 1024):
            yield chunk
        yield self.suffix
