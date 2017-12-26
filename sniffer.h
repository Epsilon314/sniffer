#ifndef SNIFFER_H
#define SNIFFER_H

#include <QThread>
#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <QMetaType>

class Pkt_display {
public:
    Pkt_display() {
        sip = "";
        dip = "";
        proto = "";
        len = "";
    }
    Pkt_display(QString c_sip,QString c_dip,QString c_proto,QString c_len,const u_char* c_data) {
        sip = c_sip;
        dip = c_dip;
        len = c_len;
        pktdata = c_data;
    }
    QString sip;
    QString dip;
    QString proto;
    QString len;
    const u_char* pktdata;
};
Q_DECLARE_METATYPE(Pkt_display);

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
    static void pkt_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pktdata);
    static Pkt_display pkt_display;
private:
    bool _active;
    bool _refresh;
};




#endif // SNIFFER_H
