"""Own multipart temporary files even across cancellation/ExceptionGroup paths."""
from contextlib import asynccontextmanager

from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException, MultiPartParser


@asynccontextmanager
async def single_file_form(request):
    if request.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'multipart/form-data':
        raise HTTPException(422, '每次必须且只能上传一个 file 文件')
    parser = MultiPartParser(request.headers, request.stream(), max_files=1, max_fields=0)
    form = None
    try:
        form = await parser.parse()
        yield form
    except MultiPartException as error:
        raise HTTPException(400, str(error)) from error
    finally:
        if form is not None:
            await form.close()
        else:
            # Starlette's own error cleanup closes this list only for a direct
            # MultiPartException. BaseHTTPMiddleware can wrap it, and task
            # cancellation is a BaseException; neither must leak the spools.
            for handle in parser._files_to_close_on_error:
                handle.close()
