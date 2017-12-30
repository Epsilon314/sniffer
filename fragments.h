#ifndef FRAGMENTS_H
#define FRAGMENTS_H

struct pkt_frag_info {
    u_short ip_id;
    u_short ip_off;
    u_short len;
    u_short tlen;
    int head_size;
    u_char ip_src[4];
    u_char ip_dst[4];
    u_char ip_p;
    const u_char* hd;
    const u_char* ud;
    pkt_frag_info *next;
};

struct fragments {
    fragments *next;
    int len;
    int offset;
    int mf;
    const u_char* head;
    const u_char* data;
};

struct dg_seq {
    dg_seq *next;
    fragments *fg;
    u_char ip_src[4];
    u_char ip_dst[4];
    u_short ip_id;
    u_char ip_p;
    int len;
    dg_seq() {
        next = NULL;
        fg = NULL;
    }
    dg_seq(const dg_seq& c) {
        next = c.next;
        fg = c.fg;
        for (int i = 0; i  < 4; i++) {
            ip_src[i] = c.ip_src[i];
            ip_dst[i] = c.ip_dst[i];
        }
        ip_id = c.ip_id;
        ip_p = c.ip_p;
        len = c.len;
    }
};

#endif // FRAGMENTS_H
