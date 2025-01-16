import os, sys

def add_build_to_path(name='build'):
    index = os.getcwd().split('/').index('crypto-calcul')
    path = '/'.join(os.getcwd().split('/')[:index+1] + [name])
    sys.path.append(path)