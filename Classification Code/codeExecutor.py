from Data_Analysis.main import Activator


def main():
    print("The program started")
    print("Classification in Process...")
    # reads from the pcap file and puts all the info in the file pcap_data
    Activator("NetworkData.pcap", "../training_set.csv", "pcap_data.csv")
    print("Classification is done, cheack the file pcap_data, column is_iot. 0 is fot not iot and 1 is for iot")


if '__main__' == __name__:
    main()
