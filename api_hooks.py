import os
import sys
import frida
from win32 import win32process
from win32.lib import win32con


def main():
    startupInfo = win32process.STARTUPINFO()
    hProcess, hThread, pid, tid = win32process.CreateProcess(
        sys.argv[1], None, None, None, 0, win32con.CREATE_SUSPENDED, None, None, startupInfo)

    session = frida.attach(pid)

    with open("_agent.js") as f:
        script = session.create_script(f.read())
    script.on('message', on_message)
    script.load()

    win32process.ResumeThread(hThread)
    sys.stdin.read()


def on_message(message, data):
    print(message)
    pass


if __name__ == "__main__":
    main()
