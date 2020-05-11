from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

from Base import *


class NetworkDataExtractor(object):
    def __init__(self):
        self.devs_fea = {}

    def process(self, devs, cache):
        self.devs_fea = DevFeatures.copy_from_devdata(devs)
        for ts, pack in cache:
            if Ether not in pack:
                continue
            mc = pack[Ether].src
            if mc not in devs.keys():
                continue
            self.collect_dns(mc, pack)
        return self.devs_fea

    def extract_feas(self, devs_fea, ts, pack):
        self.devs_fea = devs_fea
        if Ether not in pack:
            return self.devs_fea
        mc = pack[Ether].src
        if mc not in self.devs_fea.keys():
            return self.devs_fea
        self.collect_dns(mc, pack)
        return self.devs_fea

    def collect_dns(self, mac, pack):
        if UDP not in pack:
            return
        if pack[UDP].dport != 53:
            return
        if DNS not in pack:
            return
        dom = None
        try:
            dom = str(pack[DNS].qd.qname)
            splt = dom.split('.')
            dl = 4
            if len(splt) > dl:
                dom = '.'.join(splt[-dl:])
        except:
            print 'error - dns no dom'
        if dom is not None:
            self.devs_fea[mac].dns.append(dom)
        return

