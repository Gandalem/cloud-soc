"""Bounded output streaming for public image operations on the Linux host."""
import codecs
from collections import deque
import errno
import os
import re
import selectors
import signal
import subprocess
import struct
import sys
import time


def run(argv, *, env, timeout, idle_timeout):
    """Return only a bounded diagnostic tail; terminate this command group on exit."""
    import fcntl
    import pty
    import termios
    started = activity = time.monotonic()
    tail = bytearray()
    # Docker hides byte progress on a pipe. A private output terminal retains
    # those updates so a slow, advancing large layer is not treated as idle.
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 120, 0, 0))
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    with process:
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(master, selectors.EVENT_READ)
                decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                seen = deque(maxlen=512)
                pending = ''
                while selector.get_map() or process.poll() is None:
                    now = time.monotonic()
                    remaining = min(timeout - (now - started), idle_timeout - (now - activity))
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    for key, _ in selector.select(min(remaining, 1)):
                        try:
                            chunk = os.read(key.fd, 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            chunk = b''  # A closed PTY reports EIO on Linux.
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        tail.extend(chunk)
                        del tail[:-65536]
                        text = decoder.decode(chunk)
                        pending += text
                        lines = re.split(r'[\r\n]', pending)
                        pending = lines.pop()[-4096:]
                        for line in lines:
                            value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line).strip()
                            if value and value not in seen:
                                seen.append(value)
                                activity = time.monotonic()
                        sys.stdout.write(text)
                        sys.stdout.flush()
                sys.stdout.write(decoder.decode(b'', final=True))
                sys.stdout.flush()
            code = process.wait()
            completed = True
            return code, tail.decode('utf-8', errors='replace')
        finally:
            # This is a new session belonging to this invocation, never dockerd
            # or other running services. Also reap descendants holding the pipe.
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            os.close(master)

