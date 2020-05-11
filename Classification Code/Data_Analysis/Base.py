import numpy as np


class DevData(object):
    def __init__(self, mac, desc, isiot):
        self.mac = mac
        self.desc = desc
        self.isiot = int(isiot)


class DevFeatures(DevData):
    def __init__(self, mac, desc, isiot):
        super(DevFeatures, self).__init__(mac, desc, isiot)
        self.dns = []


    @staticmethod
    def copy_from_devdata(devs):
        res = {}
        for dev in devs.values():
            df = DevFeatures(dev.mac, dev.desc, dev.isiot)
            res[dev.mac] = df
        return res
