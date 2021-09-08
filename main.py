from Site import Site
import argparse
from os import path
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan sites')
    parser.add_argument('-f', type=str, required= True,
                        help='File for read sites')
    args = parser.parse_args()
    if str(path.isfile(args.f)):
        file = open(args.f, 'r')
        for line in file.readlines():
            line = line[:-1]
            if len(line.split(';')) == 2:
                proto = line.split(';')[0]
                site = line.split(';')[1]
            else:
                site = line
                proto = None
            d = Site(site, proto=proto).generateJson()
            print(d)
    else:
        print('El fichero {0} no existe'.format(args.f))