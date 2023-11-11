#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from time import sleep

ENTITY = json.loads(open("entities.json", 'r').read())


def start(ents):
    cwd = os.getcwd()

    for ent in ents:
        ent_info = ENTITY[ent]
        # os.chdir(ent_info["dir"])
        print(os.getcwd())
        _args = ["./entity.py", ent, ent_info["config"], ent_info["dir"]]
        print(_args)
        # _res = subprocess.Popen(_args, env=dict(os.environ), stdout=subprocess.DEVNULL,
        #                         stderr=subprocess.DEVNULL)
        _res = subprocess.Popen(_args, env=dict(os.environ))
        # _res = subprocess.run(_args, env=dict(os.environ))
        print(_res)
        sleep(1)


def kill(ents):
    _process = subprocess.Popen(['ps', '-ax'], stdout=subprocess.PIPE)
    output, error = _process.communicate()
    # print(output)
    for line in output.splitlines():
        for _ent in ents:
            if ENTITY[_ent]["config"] in str(line):
                pid = int(line.split(None, 1)[0])
                os.kill(pid, 9)
                break


def restart(ents):
    kill(ents)
    start(ents)


if __name__ == "__main__":
    if sys.argv[1] == "start":
        start(sys.argv[2:])
    elif sys.argv[1] == "kill" or sys.argv[1] == "stop":
        kill(sys.argv[2:])
