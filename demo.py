import argparse
import os
import sys
import math

from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader
from scapy.layers.inet import IP, TCP


def calc_entropy(file_name):  # функция для подсчета энтропии некоторого файла
    count = 0  # количество TCP и IPv4 пакетов
    slov = {}  # словарь для уникальных IP-адресов и их кол-ва
    prob = {}  # словарь для уникальных IP-адресов и их вероятности
    entropy = 0  # искомая энтропия

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue

        if ether_pkt.type != 0x0800:  # отсекаем не IPv4-пакеты
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:  # отсекаем не TCP-пакеты
            continue

        count += 1  # подсчет количества нужных файлов

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        ether_pkt_1 = Ether(pkt_data)
        if 'type' not in ether_pkt_1.fields:
            continue

        if ether_pkt_1.type != 0x0800:  # отсекаем не IPv4-пакеты
            continue

        ip_pkt_1 = ether_pkt_1[IP]
        if ip_pkt_1.proto != 6:  # отсекаем не TCP-пакеты
            continue

        if ip_pkt_1.dst in slov:  # считаем количества различных IP-адресов назначения
            slov[ip_pkt_1.dst] += 1
        else:
            slov[ip_pkt_1.dst] = 1

        if ip_pkt_1.src in slov:  # считаем количества различных IP-адресов сервера
            slov[ip_pkt_1.src] += 1
        else:
            slov[ip_pkt_1.src] = 1

        for key in slov:
            prob[key] = slov[key] / count  # подсчет вероятностей

        for key in prob:
            entropy += (-1) * prob[key] * math.log2(prob[key])  # подсчет энтропии

    return entropy, prob;


def process_pcap(file_name_1, file_name_2):
    print('Opening {}...'.format(file_name_1))
    print('Opening {}...'.format(file_name_2))
    ent1, prob1 = calc_entropy(file_name_1)
    ent2, prob2 = calc_entropy(file_name_2)

    print('Энтропия 1 дампа: ' + str(ent1))
    print('Энтропия 2 дампа: ' + str(ent2))
    diver = 0
    array_of_prob1 = []
    array_of_prob2 = []
    for i in prob1:
        array_of_prob1.append(prob1[i])
    for i in prob2:
        array_of_prob2.append(prob2[i])

    if len(array_of_prob1) > len(array_of_prob2):  # формула дивергенции
        for i in range(0, len(prob2)):
            diver += array_of_prob1[i] * (math.log2(array_of_prob1[i]) - math.log2(array_of_prob2[i]))
    else:
        for i in range(0, len(prob1)):
            diver += array_of_prob1[i] * (math.log2(array_of_prob1[i]) - math.log2(array_of_prob2[i]))
    print('Значение дивергенции: ' + str(diver))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')  # создание парсера
    parser.add_argument('--pcap1', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)  # аргумент для 1 файла
    parser.add_argument('--pcap2', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)  # аргумент для 2 файла
    args = parser.parse_args()

    file_name_1 = args.pcap1
    file_name_2 = args.pcap2
    if not os.path.isfile(file_name_1):  # проверка существования
        print('"{}" does not exist'.format(file_name_1), file=sys.stderr)
        sys.exit(-1)

    if not os.path.isfile(file_name_2):  # проверка существования
        print('"{}" does not exist'.format(file_name_2), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name_1, file_name_2)
    sys.exit(0)
