#ifndef SNIFFER_H
#define SNIFFER_H

#include <QThread>
#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <QMetaType>
#include <fragments.h>

class Pkt_display {
public:
    Pkt_display() {
        sip = "";
        dip = "";
        eth_proto = "";
        ip_proto = "";
        trans_proto = "";
        ip_uid = "";
        ip_offset = "";
        len = "";
    }
    Pkt_display(QString c_sip,QString c_dip,QString c_eth_proto, QString c_trans_proto,
                QString c_ip_uid,QString c_ip_offset,QString c_ip_proto,QString c_len,const u_char* c_data) {
        sip = c_sip;
        dip = c_dip;
        eth_proto = c_eth_proto;
        ip_proto = c_ip_proto;
        trans_proto = c_trans_proto;
        ip_uid = c_ip_uid;
        ip_offset = c_ip_offset;
        len = c_len;
        pktdata = c_data;
    }
    QString sip;
    QString dip;
    QString eth_proto;
    QString ip_proto;
    QString trans_proto;
    QString ip_uid;
    QString ip_offset;
    QString len;
    const u_char* pktdata;
};
Q_DECLARE_METATYPE(Pkt_display)

struct eth_header {
    u_char eth_dhost[6];	//destination address
    u_char eth_shost[6];	//source address
    u_short eth_type;
};

struct ip_header {
    u_char  ip_vhl;
    u_char  ip_tos;         // type of service
    u_short ip_len;         // total length
    u_short ip_id;          // identification
    u_short ip_off;         // fragment offset field
    u_char  ip_ttl;         // time to live
    u_char  ip_p;           // protocol
    u_short ip_sum;         // checksum
    u_char ip_src[4];       // source address
    u_char ip_dst[4];       // dest address
};

struct tcp_header {
    u_short th_sport;       // source port
    u_short th_dport;       // destination port
    u_int th_seq;           // sequence number
    u_int th_ack;           // acknowledgement number
    u_char th_offx2;        // data offset, rsvd
    u_char th_flags;
    u_short th_win;         // window
    u_short th_sum;         // checksum
    u_short th_urp;         // urgent pointer
};



class Sniffer_thread:public QThread {
    Q_OBJECT
signals:
    void pkt_info(Pkt_display);
public:
    void run();
    ~Sniffer_thread() {}
    void disable();
    void enable();
    bool disactived();
    static void pkt_handler(u_char *, const struct pcap_pkthdr *header, const u_char *pktdata);
    static Pkt_display pkt_display;
    static pkt_frag_info pkt_frag;
    bool ip_Fragment_reassamble(bool);
    void set_mode_reassamble(bool);
    bool check_all_fragments(dg_seq d);
private:
    bool _active;
    bool _refresh;
    bool _reassamble;
};






#endif // SNIFFER_H
