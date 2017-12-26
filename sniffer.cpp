#include "sniffer.h"
#include "mainwindow.h"

QString p_dev;
Pkt_display Sniffer_thread::pkt_display;

void Sniffer_thread::pkt_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pktdata) {
    eth_header *eth = (eth_header*)pktdata;
    pkt_display.len = QString::number(header->len);
    if(header->len >= 14) {
        ip_header *ip = (ip_header*)(pktdata+14);
        switch(ip->ip_p) {
            case IPPROTO_TCP:
                pkt_display.proto = QString("TCP");
                break;
            case IPPROTO_UDP:
                pkt_display.proto = QString("UDP");
                break;
            case IPPROTO_ICMP:
                pkt_display.proto = QString("ICMP");
                break;
            case IPPROTO_IP:
                pkt_display.proto = QString("IP");
                break;
            default:
                pkt_display.proto = QString("UNKNOWN");
                break;
        }
        pkt_display.sip = QString("%1.%2.%3.%4").arg(ip->ip_src[0]).arg(ip->ip_src[1]).arg(ip->ip_src[2]).arg(ip->ip_src[3]);
        pkt_display.dip = QString("%1.%2.%3.%4").arg(ip->ip_dst[0]).arg(ip->ip_dst[1]).arg(ip->ip_dst[2]).arg(ip->ip_dst[3]);
    }
    pkt_display.pktdata = pktdata;
}

void Sniffer_thread::run() {
    _active = true;
    _refresh = true;
    const char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_exp[] = "ip";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    while(_active) {
        if (_refresh) {
            _refresh = false;
            dev = p_dev.toStdString().c_str();
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            exit(1);
            }
            handle = pcap_open_live(dev, 1600, 1, 1000, errbuf);
            if (handle == NULL) {
                exit(1);
            }
            if (pcap_datalink(handle) != DLT_EN10MB) {
            exit(1);
            }
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                exit(1);
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                exit(1);
            }
        }
        pcap_loop(handle, 1, pkt_handler, NULL);
        //printf("%s %s %s \n",proto.toStdString().c_str(),sip.toStdString().c_str(),dip.toStdString().c_str());
        emit pkt_info(pkt_display);
    }
}

void Sniffer_thread::disable() {
    _active = false;
}

void Sniffer_thread::enable() {
    _active = true;
    _refresh = true;
}

bool Sniffer_thread::disactived() {
    return !_active;
}

