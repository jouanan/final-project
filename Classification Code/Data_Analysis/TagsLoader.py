from Base import *


# read from training_set file and set for each device according
# if it is iot or not


class DeviceTagsLoader(object):
    def __init__(self, tagfile):
        self.devs = {}
        filel = open(tagfile, 'r')
        data = filel.read()
        lines = data.replace('\r', '').split('\n')
        for ln in lines:
            if not self.is_valid(ln):
                continue
            mac = ln.split(',')[0]
            name = ln.split(',')[1]
            isiot = ln.split(',')[2]
            dd = DevData(mac, name, isiot)
            if mac in self.devs.keys():
                continue
            self.devs[mac] = dd
        filel.close()


    @staticmethod
    def is_valid(ln):
        splt = ln.split(',')
        if len(splt) != 3:
            return False
        try:
            int(splt[2])
        except ValueError:
            return False
        return True

