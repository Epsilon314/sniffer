#include "sniffer.h"
#include "mainwindow.h"


QString p_dev;
QString p_filter;
Pkt_display Sniffer_thread::pkt_display;
pkt_frag_info Sniffer_thread::pkt_frag;
pcap_dumper_t *dumpfile;
extern const char* p_path;

dg_seq head;

void Sniffer_thread::pkt_handler(u_char *dumpfile, const struct pcap_pkthdr *header,
                                 const u_char *pktdata) {

    pcap_dump(dumpfile,header,pktdata);
    eth_header *eth = (eth_header*)pktdata;
    pkt_display.smac = QString("%1:%2:%3:%4:%5:%6").arg(eth->eth_shost[0])
                                                   .arg(eth->eth_shost[1])
                                                   .arg(eth->eth_shost[2])
                                                   .arg(eth->eth_shost[3])
                                                   .arg(eth->eth_shost[4])
                                                   .arg(eth->eth_shost[5]);

    pkt_display.dmac = QString("%1:%2:%3:%4:%5:%6").arg(eth->eth_dhost[0])
                                                   .arg(eth->eth_dhost[1])
                                                   .arg(eth->eth_dhost[2])
                                                   .arg(eth->eth_dhost[3])
                                                   .arg(eth->eth_dhost[4])
                                                   .arg(eth->eth_dhost[5]);
    switch (ntohs(eth->eth_type)) {
    case 0x0800:
        pkt_display.eth_proto = QString("IP");
        break;
    case 0x0806:
        pkt_display.eth_proto = QString("ARP");
        break;
    case 0x8035:
        pkt_display.eth_proto = QString("RARP");
        break;
    case 0x86dd:
        pkt_display.eth_proto = QString("IPv6");
        break;
    case 0x8864:
        pkt_display.eth_proto = QString("PPPoE");
        break;
    default:
        pkt_display.eth_proto = QString("UNKNOWN");
        break;
    }
    pkt_display.len = QString::number(header->len);
    pkt_frag.tlen = header->len;

    if(header->len >= 14) {

        ip_header *ip = (ip_header*)(pktdata+14);

        pkt_frag.ip_id = ip->ip_id;
        pkt_frag.ip_off = ip->ip_off;
        pkt_frag.len = ip->ip_len;
        for (int i = 0; i < 4; i++) {
            pkt_frag.ip_src[i] = ip->ip_src[i];
            pkt_frag.ip_dst[i] = ip->ip_dst[i];
        }

        switch(ip->ip_p) {
        case IPPROTO_TCP:
            pkt_display.ip_proto = QString("TCP");
            break;

        case IPPROTO_UDP:
            pkt_display.ip_proto = QString("UDP");
            break;

        case IPPROTO_ICMP:
            pkt_display.ip_proto = QString("ICMP");
            break;

        case IPPROTO_IP:
            pkt_display.ip_proto = QString("IP");
            break;

        case IPPROTO_IGMP:
            pkt_display.ip_proto = QString("IGMP");
            break;

        default:
            pkt_display.ip_proto = QString("UNKNOWN");
            break;

        }

        pkt_display.sip = QString("%1.%2.%3.%4").arg(ip->ip_src[0])
                .arg(ip->ip_src[1]).arg(ip->ip_src[2]).arg(ip->ip_src[3]);
        pkt_display.dip = QString("%1.%2.%3.%4").arg(ip->ip_dst[0])
                .arg(ip->ip_dst[1]).arg(ip->ip_dst[2]).arg(ip->ip_dst[3]);

        int ip_size = (ip->ip_vhl & 0x0f) * 4;
        pkt_frag.head_size = ip_size;
        if (ip->ip_p == IPPROTO_TCP) {
            tcp_header *tcp = (tcp_header *)(pktdata + 14 + ip_size);
            pkt_display.sport = QString::number(ntohs(tcp->th_sport));
            pkt_display.dport = QString::number(ntohs(tcp->th_dport));
            switch (tcp->th_dport) {
            case 0x5000:
                pkt_display.trans_proto = QString("HTTP");
                break;
            case 0x1400:
            case 0x1500:
                pkt_display.trans_proto = QString("TCP");
                break;
            case 0x1700:
                pkt_display.trans_proto = QString("TELNET");
                break;
            case 0x1900:
                pkt_display.trans_proto = QString("SMTP");
                break;
            case 0x3500:
                pkt_display.trans_proto = QString("DNS");
                break;
            case 0x6e00:
                pkt_display.trans_proto = QString("POP3");
                break;
            case 0xbb01:
                pkt_display.trans_proto = QString("HTTPS");
                break;
            }
            switch (tcp->th_sport) {
            case 0x5000:
                pkt_display.trans_proto = QString("HTTP");
                break;
            case 0x1400:
            case 0x1500:
                pkt_display.trans_proto = QString("TCP");
                break;
            case 0x1700:
                pkt_display.trans_proto = QString("TELNET");
                break;
            case 0x1900:
                pkt_display.trans_proto = QString("SMTP");
                break;
            case 0x3500:
                pkt_display.trans_proto = QString("DNS");
                break;
            case 0x6e00:
                pkt_display.trans_proto = QString("POP3");
                break;
            case 0xbb01:
                pkt_display.trans_proto = QString("HTTPS");
                break;
            default:
                pkt_display.trans_proto = QString("UNKNOWN");
            }
        }
    }
    pkt_display.pktdata = pktdata;
}

void Sniffer_thread::run() {
    _active = true;
    _refresh = true;
    const char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *filter_exp;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    while(_active) {
        if (_refresh) {
            _refresh = false;
            dev = p_dev.toStdString().c_str();
            filter_exp = p_filter.toStdString().c_str();
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
            dumpfile = pcap_dump_open(handle,p_path);
        }
        pcap_loop(handle, 1, pkt_handler, (unsigned char*)dumpfile);
        if (ip_Fragment_reassamble(_reassamble)) {
            emit pkt_info(pkt_display);
        }
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

bool Sniffer_thread::check_all_fragments(dg_seq d) {
    int totalLen = 0;
    fragments *f;
    f = d.fg;
    while(f->next != NULL) {
        totalLen += f->len;
    }
    if (totalLen == d.len) {
        pkt_display.len = d.len;
        //code to assemble datagram
        return true;
    }
    else return false;
}


bool Sniffer_thread::ip_Fragment_reassamble(bool enable) {
    if(enable) {
        //printf("%04x ",pkt_frag.ip_off);

        int df = pkt_frag.ip_off & 0x0040;
        if (pkt_frag.ip_off == 0 || df != 0) {
            return true;
        }

        fragments f;
        f.mf = ntohs(pkt_frag.ip_off) & 0x2000;
        f.offset = ntohs(pkt_frag.ip_off) & 0x1fff;
        int id = ntohs(pkt_frag.ip_id);
        f.len = pkt_frag.len;
        f.head = pkt_frag.ud + 14;
        f.data = pkt_frag.ud + 14 + pkt_frag.head_size;

        dg_seq *d;
        d = &head;
        bool find = false;
        while (d->next != NULL) {
            d = d->next;
            bool flag = true;
            for(int i = 0; i < 4; i ++) {
                if (d->ip_src[i] != pkt_frag.ip_src[i]) flag = false;
                if (d->ip_dst[i] != pkt_frag.ip_dst[i]) flag = false;
            }
            if (id != d->ip_id) flag = false;
            if (pkt_frag.ip_p != d->ip_p) flag = false;
            if(flag) {
                find = true;
                fragments *insert_f;
                insert_f = d->fg;
                while (insert_f->next != NULL) insert_f = insert_f->next;
                insert_f->next = &f;
                return check_all_fragments(*d);
            }
        }
        if (!find) {
            dg_seq nd;
            for (int i = 0; i < 4; i ++) {
                nd.ip_src[i] = pkt_frag.ip_src[i];
                nd.ip_dst[i] = pkt_frag.ip_dst[i];
            }
            nd.ip_id = id;
            nd.ip_p = pkt_frag.ip_p;
            nd.len = pkt_frag.tlen;
            nd.fg = &f;
            dg_seq *insert_d;
            insert_d = &head;
            while (insert_d->next != NULL) insert_d = insert_d->next;
            insert_d = &nd;
            return check_all_fragments(nd);
        }
    }
    else {
        return true;
    }
    return false;
}

void Sniffer_thread::set_mode_reassamble(bool enable) {
   _reassamble = enable;
}

void Sniffer_thread::saveDump() {
    pcap_dump_close(dumpfile);
}
