#ifndef NETLINK_HELPER_H
#define NETLINK_HELPER_H

#include <stdio.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <netlink/attr.h>

#ifdef DEBUG
#define NLA_DBG(fmt, ...) fprintf(stdout, "[dbg] %s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define NLA_DBG(fmt, ...) do { } while (0)
#endif

static inline uint8_t nla_get_u8_safe(const struct nlattr *nla){
    if (!nla) { NLA_DBG("null attr\n"); return 0; }
    int len = nla_len(nla);
    if (len < (int)sizeof(uint8_t)) {
        NLA_DBG("short payload need=%zu got=%d\n", sizeof(uint8_t), len);
        return 0;
    }
    return nla_get_u8(nla);
}

static inline uint16_t nla_get_u16_safe(const struct nlattr *nla){
    if (!nla) { NLA_DBG("null attr\n"); return 0; }
    int len = nla_len(nla);
    if (len < (int)sizeof(uint16_t)) {
        NLA_DBG("short payload need=%zu got=%d\n", sizeof(uint16_t), len);
        return 0;
    }
    return nla_get_u16(nla);
}

static inline uint32_t nla_get_u32_safe(const struct nlattr *nla){
    if (!nla) { NLA_DBG("null attr\n"); return 0; }
    int len = nla_len(nla);
    if (len < (int)sizeof(uint32_t)) {
        NLA_DBG("short payload need=%zu got=%d\n", sizeof(uint32_t), len);
        return 0;
    }
    return nla_get_u32(nla);
}

static inline uint64_t nla_get_u64_safe(const struct nlattr *nla){
    if (!nla) { NLA_DBG("null attr\n"); return 0; }
    int len = nla_len(nla);
    if (len < (int)sizeof(uint64_t)) {
        NLA_DBG("short payload need=%zu got=%d\n", sizeof(uint64_t), len);
        return 0;
    }
    return nla_get_u64(nla);
}

#endif /* NETLINK_HELPER_H */
