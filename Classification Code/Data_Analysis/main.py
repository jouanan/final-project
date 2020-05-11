
# Purpose:
#
# Read two types of files:
# - a pcap contains communication of IOT/NOT
# - a txt/csv file that contains tagging to the device's MAC (isiot & desc, for debugging)

from TagsLoader import DeviceTagsLoader
from PcapIO import *


class Activator(object):
    def __init__(self, pcap, oracle_file, outfile):
        oracle = DeviceTagsLoader(oracle_file).devs
        writer = LogWriter(outfile, oracle)
        self.pcap = pcap

        slot_60 = SlotCache(60, oracle, writer)
        slot_120 = SlotCache(120, oracle, writer)
        slot_180 = SlotCache(180, oracle, writer)
        slot_240 = SlotCache(240, oracle, writer)
        slot_300 = SlotCache(300, oracle, writer)
        slot_600 = SlotCache(600, oracle, writer)
        slot_1200 = SlotCache(1200, oracle, writer)

        self.pcap_reader = PcapReader(self.pcap)
        self.pcap_reader.add_cacher(slot_60)
        self.pcap_reader.add_cacher(slot_120)
        self.pcap_reader.add_cacher(slot_180)
        self.pcap_reader.add_cacher(slot_240)
        self.pcap_reader.add_cacher(slot_300)
        self.pcap_reader.add_cacher(slot_600)
        self.pcap_reader.add_cacher(slot_1200)
        self.pcap_reader.read()

if '__main__' == __name__:
    pass
