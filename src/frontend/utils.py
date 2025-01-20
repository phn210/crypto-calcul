import os, platform, sys

def add_build_to_path(name='build'):
    path_sep = '/'
    if platform.system() == 'Windows':
        path_sep = '\\'
    index = os.getcwd().split(path_sep).index('crypto-calcul')
    path = path_sep.join(os.getcwd().split(path_sep)[:index+1] + [name])
    sys.path.append(path)