import pcapy
from scapy.layers.l2 import Ether
from Base import *
from NetworkDataExtractor import NetworkDataExtractor


class PcapReader(object):
    def __init__(self, pcapfile, bpf=None):
        self._cachers = []
        self._pcapfile_name = pcapfile
        self._pc = pcapy.open_offline(pcapfile)
        self._bpf = bpf
        if bpf is not None:
            self._pc.setfilter(bpf)

    def read(self):
        packet_index = 0
        while True:
            try:
                (header, pack) = self._pc.next()
                if header is None or pack is None:
                    break
                ts = (header.getts()[0] * 10 ** 6 + header.getts()[1]) / 10. ** 6
                packet_index += 1

                pack = Ether(pack)
                for sc in self._cachers:
                    sc.add(ts, pack)

                if packet_index % 10000 == 0:
                    print packet_index

            except pcapy.PcapError:
                break
        return

    def load_pcap(self, pcap, bpf=None):
        self._pc = pcapy.open_offline(pcap)
        self._bpf = bpf
        if bpf is not None:
            self._pc.setfilter(bpf)
        elif self._bpf is not None:
            self._pc.setfilter(self._bpf)
        return
#jouana
    def add_cacher(self, slot_cache):
        self._cachers.append(slot_cache)
        return


class SlotCache(object):
    def __init__(self, slot_width, oracle, writer):
        self.sd = slot_width
        self.slot_id = 0
        self._oracle = oracle
        self._dev_fea = DevFeatures.copy_from_devdata(oracle)

        if type(writer) is LogWriter:
            self._writer = writer
        else:
            raise AssertionError('Wrong Writer Type')

    def __del__(self):
        self._writer.log_record(self.slot_id, self.sd, self._dev_fea)

    def add(self, ts, pack):
        if self.slot_id == 0:
            self.slot_id = ts
        if ts > self.slot_id + self.sd or ts < self.slot_id:
            self._writer.log_record(self.slot_id, self.sd, self._dev_fea)  # # call writer
            self.slot_id = ts
            del self._dev_fea
            self._dev_fea = DevFeatures.copy_from_devdata(self._oracle)
            self._dev_fea = NetworkDataExtractor().extract_feas(self._dev_fea, ts, pack)
            return
        self._dev_fea = NetworkDataExtractor().extract_feas(self._dev_fea, ts, pack)
        pass


class LogWriter(object):
    def __init__(self, out_file_name, oracle):
        self._oracle = oracle
        self._ofn = out_file_name
        self._fl = open(self._ofn, 'w')
        self._write_header()

    def __del__(self):
        self._fl.close()

    def _write_header(self):
        head = str('mac')+ ','
        head += str('desc')+','
        head += str('isiot')+','
        head += str('dns') + '\n'
        self._fl.write(head)

    def log_record(self, slot_id, slot_width, packs):
        record = ''+self._compile_records(slot_id, slot_width, packs)
        self._fl.write(record)

    @staticmethod
    def _compile_records(slot_id, slot_width, devs_fea):
        res = ''
        for dev in devs_fea.values():
            res += str(dev.mac)+','
            res += str(dev.desc)+','
            res += str(dev.isiot)+','
            res += str(len(set(dev.dns)))
            res += '\n'
        return res





