import os, subprocess
from flask import request

def x():
    cmd = request.args.get('cmd')
    os.system(cmd)
    return subprocess.run('echo ' + cmd, shell=True)
