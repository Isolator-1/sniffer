from io import StringIO
import string
import sys
def stdoutCapture(func,arg,lock1,lock2):
    original_stdout = sys.stdout
    string_buffer = StringIO()
    sys.stdout = string_buffer
    func(arg)
    sys.stdout = original_stdout
    return string_buffer.getvalue()