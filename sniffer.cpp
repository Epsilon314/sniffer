#include "sniffer.h"
#include "mainwindow.h"

//settings passed from gui
QString p_dev;
QString p_filter;

//data structure containing processed data for gui-display
Pkt_display Sniffer_thread::pkt_display;

//data structure for fragments
pkt_frag_info Sniffer_thread::pkt_frag;

//dump file type defined by libpcap
pcap_dumper_t *dumpfile;

//temp save file path
extern const char* p_path;

//datagram cross-link-table head node
dg_seq head;

void Sniffer_thread::pkt_handler(u_char *dumpfile, const struct pcap_pkthdr *header,
                                 const u_char *pktdata) {
    /*
    callback func required by libpcap
    doing packet analyze work
    */
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

    //header should be large than 14 byte, otherwise drop it
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


        /*ip-vhl contain version and head length infomation,
        use bytewise & operation to extract the needed data
        */
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
                pkt_display.trans_proto = QString("FTP");
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

                switch (tcp->th_sport) {
                case 0x5000:
                    pkt_display.trans_proto = QString("HTTP");
                    break;
                case 0x1400:
                case 0x1500:
                    pkt_display.trans_proto = QString("FTP");
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
                    break;
                }
                break;
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

            //find network information
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            exit(1);
            }

            //open sniffer
            handle = pcap_open_live(dev, 1600, 1, 1000, errbuf);
            if (handle == NULL) {
                exit(1);
            }

            //check if is ethernet
            if (pcap_datalink(handle) != DLT_EN10MB) {
            exit(1);
            }

            //compile bpf expression
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                exit(1);
            }

            //apply the compiled filter
            if (pcap_setfilter(handle, &fp) == -1) {
                exit(1);
            }

            //save to file
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

bool cmpFragments(fragments &op1, fragments &op2) {
    //ascending sort
    return (op1.offset < op2.offset);
}

bool Sniffer_thread::check_all_fragments(dg_seq d) {

    //if all fragments length add up = total length
    //means have captured all fragments
    //reassamble the and tell the thread to emit the displsy snignal

    int totalLen = 0;
    fragments *f;
    f = d.fg;
    while(f->next != NULL) {
        f = f->next;
        totalLen += f->len;
    }
    if (totalLen == d.len) {
        pkt_display.len = d.len;
        //code to assemble datagram
        f = d.fg;
        std::vector<fragments> collect;
        while (f->next != NULL) {
            f = f->next;
            collect.insert(collect.end(),*f);
        }
        std::sort(collect.begin(),collect.end(),cmpFragments);
        std::stringstream totalpl;
        for(std::vector<fragments>::iterator iter = collect.begin();
            iter != collect.end(); iter++) {
            totalpl << std::string((char*)*iter->data);
        }
        std::string pl = totalpl.str();
        pkt_display.pktdata = (u_char*)pl.c_str();
        return true;
    }
    else return false;
}


bool Sniffer_thread::ip_Fragment_reassamble(bool enable) {
    if(enable) {
        //printf("%04x ",pkt_frag.ip_off);

        //don't frag symbol
        int df = pkt_frag.ip_off & 0x0040;

        //if offset all zero, it means the packet is not fragmented
        //if don't frag symbol is set, the packet is not allowed to be fragmented
        if (pkt_frag.ip_off == 0 || df != 0) {
            return true;
        }

        //use a cross link-list to do collect and reassamble work
        //should add time-out mechanism to save memory
        fragments f;
        f.mf = ntohs(pkt_frag.ip_off) & 0x2000;

        //extract the offset value
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
            //say two fragments belong to one datagram
            //if they have same source ip, dst ip, ip_id and ip protocol
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
