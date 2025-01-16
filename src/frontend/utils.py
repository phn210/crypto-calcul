import platform

def add_build_to_path(name='build'):
    path_sep = '/'
    if platform.system() == 'Windows':
        path_sep = '\\'
    index = platform.os.getcwd().split(path_sep).index('crypto-calcul')
    path = path_sep.join(platform.os.getcwd().split(path_sep)[:index+1] + [name])
    platform.sys.path.append(path)