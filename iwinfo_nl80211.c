/*
 * iwinfo - Wireless Information Library - NL80211 Backend thread safe version
 *
 *   Copyright (C) 2024 Ruslan Isaev <legale.legale@gmail.com>
 *
 */

#include <fnmatch.h>
#include <glob.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "include/iwinfo-mt.h"
#include "iwinfo_nl80211-mt.h"
#include "netlink-helper.h"

#define min(x, y) ((x) < (y)) ? (x) : (y)

#define BIT(x) (1ULL << (x))

void nl80211_close(nl80211_state_t *state) {
  if (state->nlctrl)
    (void)genl_family_put(state->nlctrl);

  if (state->nl80211)
    (void)genl_family_put(state->nl80211);

  if (state->nl_sock)
    (void)nl_socket_free(state->nl_sock);

  if (state->nl_cache)
    (void)nl_cache_free(state->nl_cache);
}

nl80211_state_t *nl80211_init(iwinfo_t *container) {
  int fd;
  if (container == NULL)
    return NULL;
  nl80211_state_t *state = &container->state;

  state->nl_sock = nl_socket_alloc();
  if (!state->nl_sock) {
    goto err;
  }

  if (genl_connect(state->nl_sock)) {
    goto err;
  }

  fd = nl_socket_get_fd(state->nl_sock);
  if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) < 0) {
    goto err;
  }

  if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
    goto err;
  }

  state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
  if (!state->nl80211) {
    goto err;
  }

  state->nlctrl = genl_ctrl_search_by_name(state->nl_cache, "nlctrl");
  if (!state->nlctrl) {
    goto err;
  }

  return state;

err:
  nl80211_close(state);
  return NULL;
}

static int nl80211_readint(const char *path) {
  int fd;
  int rv = -1;
  char buffer[16];

  if ((fd = open(path, O_RDONLY)) > -1) {
    if (read(fd, buffer, sizeof(buffer)) > 0)
      rv = atoi(buffer);

    close(fd);
  }

  return rv;
}

static int nl80211_readstr(const char *path, char *buffer, int length) {
  int fd;
  int rv = -1;

  if ((fd = open(path, O_RDONLY)) > -1) {
    if ((rv = read(fd, buffer, length - 1)) > 0) {
      if (buffer[rv - 1] == '\n')
        rv--;

      buffer[rv] = 0;
    }

    close(fd);
  }

  return rv;
}

static int nl80211_get_band(int nla_type) {
  switch (nla_type) {
  case NL80211_BAND_2GHZ:
    return IWINFO_BAND_24;
  case NL80211_BAND_5GHZ:
    return IWINFO_BAND_5;
  case NL80211_BAND_6GHZ:
    return IWINFO_BAND_6;
  case NL80211_BAND_60GHZ:
    return IWINFO_BAND_60;
  }

  return 0;
}

static int nl80211_msg_error(struct sockaddr_nl *nla, struct nlmsgerr *err,
                             void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int nl80211_msg_finish(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int nl80211_msg_ack(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int nl80211_msg_response(struct nl_msg *msg, void *arg) {
  return NL_SKIP;
}

static void nl80211_free(struct nl80211_msg_conveyor *cv) {
  // NLA_DBG("%s\n", __func__);

  if (cv) {
    if (cv->cb)
      nl_cb_put(cv->cb);

    if (cv->msg)
      nlmsg_free(cv->msg);

    cv->cb = NULL;
    cv->msg = NULL;
  }
}

static struct nl80211_msg_conveyor *
nl80211_new(iwinfo_t *iw, struct genl_family *family, int cmd, int flags) {

  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  cv->msg = nlmsg_alloc();
  if (!cv->msg)
    goto err;

  cv->cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cv->cb)
    goto err_msg;

  genlmsg_put(cv->msg, 0, 0, genl_family_get_id(family), 0, flags, cmd, 0);

  return cv;

err_msg:
  nlmsg_free(iw->state.cv.msg);
err:
  return NULL;
}

static struct nl80211_msg_conveyor *nl80211_ctl(iwinfo_t *iw, int cmd,
                                                int flags) {
  if (iw == NULL)
    return NULL;

  return nl80211_new(iw, iw->state.nlctrl, cmd, flags);
}

static const char *nl80211_phy_path_str(const char *phyname) {
  static char path[PATH_MAX];
  const char *prefix = "/sys/devices/";
  int prefix_len = strlen(prefix);
  int buf_len, offset;
  struct dirent *e;
  char buf[512], *link;
  int phy_idx;
  int seq = 0;
  DIR *d;

  snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", phyname);
  phy_idx = nl80211_readint(buf);
  if (phy_idx < 0)
    return NULL;

  buf_len =
      snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/device", phyname);
  link = realpath(buf, path);
  if (!link)
    return NULL;

  if (strncmp(link, prefix, prefix_len) != 0)
    return NULL;

  link += prefix_len;

  prefix = "platform/";
  prefix_len = strlen(prefix);
  if (!strncmp(link, prefix, prefix_len) && strstr(link, "/pci"))
    link += prefix_len;

  snprintf(buf + buf_len, sizeof(buf) - buf_len, "/ieee80211");
  d = opendir(buf);
  if (!d)
    return link;

  while ((e = readdir(d)) != NULL) {
    int cur_idx;

    snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", e->d_name);
    cur_idx = nl80211_readint(buf);
    if (cur_idx < 0)
      continue;

    if (cur_idx >= phy_idx)
      continue;

    seq++;
  }

  closedir(d);

  if (!seq)
    return link;

  offset = link - path + strlen(link);
  snprintf(path + offset, sizeof(path) - offset, "+%d", seq);

  return link;
}

static int nl80211_phy_idx_from_path(const char *path) {
  char buf[512];
  struct dirent *e;
  const char *cur_path;
  int cur_path_len;
  int path_len;
  int idx = -1;
  DIR *d;

  if (!path)
    return -1;

  path_len = strlen(path);
  if (!path_len)
    return -1;

  d = opendir("/sys/class/ieee80211");
  if (!d)
    return -1;

  while ((e = readdir(d)) != NULL) {
    cur_path = nl80211_phy_path_str(e->d_name);
    if (!cur_path)
      continue;

    cur_path_len = strlen(cur_path);
    if (cur_path_len < path_len)
      continue;

    if (strcmp(cur_path + cur_path_len - path_len, path) != 0)
      continue;

    snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", e->d_name);
    idx = nl80211_readint(buf);

    if (idx >= 0)
      break;
  }

  closedir(d);

  return idx;
}

static int nl80211_phy_idx_from_macaddr(const char *opt) {
  char buf[128];
  int i, idx = -1;
  glob_t gl;

  if (!opt)
    return -1;

  snprintf(buf, sizeof(buf), "/sys/class/ieee80211/*");
  if (glob(buf, 0, NULL, &gl))
    return -1;

  for (i = 0; i < gl.gl_pathc; i++) {
    snprintf(buf, sizeof(buf), "%s/macaddress", gl.gl_pathv[i]);
    if (nl80211_readstr(buf, buf, sizeof(buf)) <= 0)
      continue;

    if (fnmatch(opt, buf, FNM_CASEFOLD))
      continue;

    snprintf(buf, sizeof(buf), "%s/index", gl.gl_pathv[i]);
    if ((idx = nl80211_readint(buf)) > -1)
      break;
  }

  globfree(&gl);

  return idx;
}

static int nl80211_phy_idx_from_phy(const char *opt) {
  char buf[128];

  if (!opt)
    return -1;

  snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", opt);
  return nl80211_readint(buf);
}

static struct nl80211_msg_conveyor *
nl80211_msg(iwinfo_t *iw, const char *ifname, int cmd, int flags) {
  unsigned int ifidx = 0;
  int phyidx = -1;

  if (iw == NULL)
    return NULL;
  if (ifname == NULL)
    return NULL;

  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  ifidx = if_nametoindex(ifname);
  /* Valid ifidx must be > 0 */
  if (ifidx == 0) {
    phyidx = nl80211_phy_idx_from_phy(ifname);
    if (phyidx < 0)
      return NULL; /* phyidx must be >= 0 */
  }

  cv = nl80211_new(iw, iw->state.nl80211, cmd, flags);
  if (!cv)
    return NULL;

  if (ifidx) {
    NLA_PUT_U32(cv->msg, NL80211_ATTR_IFINDEX, ifidx);
  } else {
    NLA_PUT_U32(cv->msg, NL80211_ATTR_WIPHY, phyidx);
  }

  return cv;

nla_put_failure:
  nl80211_free(cv);
  return NULL;
}

static int nl80211_send(iwinfo_t *iw, int (*cb_func)(struct nl_msg *, void *),
                        void *cb_arg) {
  if (iw == NULL)
    return 1;

  int err;
  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  struct nl80211_msg_conveyor rcv = {0};

  if (cb_func) {
    nl_cb_set(cv->cb, NL_CB_VALID, NL_CB_CUSTOM, cb_func, cb_arg);
  } else {
    nl_cb_set(cv->cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_msg_response, &rcv);
  }
  err = nl_send_auto_complete(iw->state.nl_sock, cv->msg);

  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cv->cb, NL_CB_CUSTOM, nl80211_msg_error, &err);
  nl_cb_set(cv->cb, NL_CB_FINISH, NL_CB_CUSTOM, nl80211_msg_finish, &err);
  nl_cb_set(cv->cb, NL_CB_ACK, NL_CB_CUSTOM, nl80211_msg_ack, &err);

  while (err > 0)
    nl_recvmsgs(iw->state.nl_sock, cv->cb);

out:
  nl80211_free(cv);
  return err;
}

static int nl80211_request(iwinfo_t *iw, const char *ifname, int cmd, int flags,
                           int (*cb_func)(struct nl_msg *, void *),
                           void *cb_arg) {
  struct nl80211_msg_conveyor *cv;
  // NLA_DBG("%s %s\n", __func__, ifname);

  cv = nl80211_msg(iw, ifname, cmd, flags);

  if (!cv)
    return -ENOMEM;

  return nl80211_send(iw, cb_func, cb_arg);
}

static struct nlattr **nl80211_parse(struct nl_msg *msg) {
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  static struct nlattr *attr[NL80211_ATTR_MAX + 1];

  nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  return attr;
}

static int nl80211_get_protocol_features_cb(struct nl_msg *msg, void *arg) {
  uint32_t *features = arg;
  struct nlattr **attr = nl80211_parse(msg);

  if (attr[NL80211_ATTR_PROTOCOL_FEATURES])
    *features = nla_get_u32_safe(attr[NL80211_ATTR_PROTOCOL_FEATURES]);

  return NL_SKIP;
}

static int nl80211_get_protocol_features(iwinfo_t *iw, const char *ifname) {
  if (iw == NULL)
    return -1;
  struct nl80211_msg_conveyor *req;
  uint32_t features = 0;

  req = nl80211_msg(iw, ifname, NL80211_CMD_GET_PROTOCOL_FEATURES, 0);
  if (req) {
    nl80211_send(iw, nl80211_get_protocol_features_cb, &features);
    nl80211_free(req);
  }

  return features;
}

static int nl80211_subscribe_cb(struct nl_msg *msg, void *arg) {
  struct nl80211_group_conveyor *cv = arg;

  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *mgrpinfo[CTRL_ATTR_MCAST_GRP_MAX + 1];
  struct nlattr *mgrp;
  int mgrpidx;

  if (!attr[CTRL_ATTR_MCAST_GROUPS])
    return NL_SKIP;

  nla_for_each_nested(mgrp, attr[CTRL_ATTR_MCAST_GROUPS], mgrpidx) {
    nla_parse(mgrpinfo, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mgrp), nla_len(mgrp),
              NULL);

    if (mgrpinfo[CTRL_ATTR_MCAST_GRP_ID] &&
        mgrpinfo[CTRL_ATTR_MCAST_GRP_NAME] &&
        !strncmp(nla_data(mgrpinfo[CTRL_ATTR_MCAST_GRP_NAME]), cv->name,
                 nla_len(mgrpinfo[CTRL_ATTR_MCAST_GRP_NAME]))) {
      cv->id = nla_get_u32_safe(mgrpinfo[CTRL_ATTR_MCAST_GRP_ID]);
      break;
    }
  }

  return NL_SKIP;
}

static int nl80211_subscribe(iwinfo_t *iw, const char *family,
                             const char *group) {
  if (iw == NULL)
    return -ENOMEM;
  struct nl80211_group_conveyor cv = {.name = group, .id = -ENOENT};
  struct nl80211_msg_conveyor *req;
  int err;

  req = nl80211_ctl(iw, CTRL_CMD_GETFAMILY, 0);
  if (req) {
    NLA_PUT_STRING(req->msg, CTRL_ATTR_FAMILY_NAME, family);
    err = nl80211_send(iw, nl80211_subscribe_cb, &cv);

    if (err)
      return err;

    return nl_socket_add_membership(iw->state.nl_sock, cv.id);

  nla_put_failure:
    nl80211_free(req);
  }

  return -ENOMEM;
}

static int nl80211_wait_cb(struct nl_msg *msg, void *arg) {
  struct nl80211_event_conveyor *cv = arg;
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

  if (cv->wait[gnlh->cmd / 32] & (1 << (gnlh->cmd % 32)))
    cv->recv = gnlh->cmd;

  return NL_SKIP;
}

static int nl80211_wait_seq_check(struct nl_msg *msg, void *arg) {
  return NL_OK;
}

static int __nl80211_wait(iwinfo_t *iw, const char *family, const char *group,
                          ...) {
  // NLA_DBG("%s\n", __func__);
  struct nl80211_event_conveyor cv = {0};
  struct nl_cb *cb;
  int err = 0;
  int cmd;
  va_list ap;

  if (nl80211_subscribe(iw, family, group))
    return -ENOENT;

  cb = nl_cb_alloc(NL_CB_DEFAULT);

  if (!cb)
    return -ENOMEM;

  nl_cb_err(cb, NL_CB_CUSTOM, nl80211_msg_error, &err);
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_wait_seq_check, NULL);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_wait_cb, &cv);

  va_start(ap, group);

  for (cmd = va_arg(ap, int); cmd != 0; cmd = va_arg(ap, int))
    cv.wait[cmd / 32] |= (1 << (cmd % 32));

  va_end(ap);

  while (!cv.recv && !err)
    nl_recvmsgs(iw->state.nl_sock, cb);

  nl_cb_put(cb);

  return err;
}

#define nl80211_wait(container, family, group, ...)                            \
  __nl80211_wait(container, family, group, __VA_ARGS__, 0)

static int nl80211_freq2channel(int freq) {
  if (freq == 2484)
    return 14;
  else if (freq < 2484)
    return (freq - 2407) / 5;
  else if (freq >= 4910 && freq <= 4980)
    return (freq - 4000) / 5;
  else if (freq < 5925)
    return (freq - 5000) / 5;
  else if (freq == 5935)
    return 2;
  else if (freq <= 45000) /* DMG band lower limit */
    /* see 802.11ax D6.1 27.3.22.2 */
    return (freq - 5950) / 5;
  else if (freq >= 58320 && freq <= 70200)
    return (freq - 56160) / 2160;
  else
    return 0;
}

static int nl80211_channel2freq(int channel, const char *band, bool ax) {
  if (channel < 1)
    return 0;

  if (!band || band[0] != 'a') {
    if (channel == 14)
      return 2484;
    else if (channel < 14)
      return (channel * 5) + 2407;
  } else if (strcmp(band, "ad") == 0) {
    if (channel < 7)
      return 56160 + 2160 * channel;
  } else if (ax) {
    if (channel == 2)
      return 5935;
    if (channel < 233)
      return (channel * 5) + 5950;
  } else {
    if (channel >= 182 && channel <= 196)
      return (channel * 5) + 4000;
    else
      return (channel * 5) + 5000;
  }

  return 0;
}

static uint8_t nl80211_freq2band(int freq) {
  if (freq >= 2412 && freq <= 2484)
    return IWINFO_BAND_24;
  else if (freq >= 5160 && freq <= 5885)
    return IWINFO_BAND_5;
  else if (freq >= 5925 && freq <= 7125)
    return IWINFO_BAND_6;
  else if (freq >= 58320 && freq <= 69120)
    return IWINFO_BAND_60;

  return 0;
}

static int nl80211_phyname_cb(struct nl_msg *msg, void *arg) {
  char *buf = arg;
  struct nlattr **attr = nl80211_parse(msg);

  if (attr[NL80211_ATTR_WIPHY_NAME])
    memcpy(buf, nla_data(attr[NL80211_ATTR_WIPHY_NAME]),
           nla_len(attr[NL80211_ATTR_WIPHY_NAME]));
  else
    buf[0] = 0;

  return NL_SKIP;
}

static char *nl80211_ifname2phy(iwinfo_t *iw, char *phy, const char *ifname) {
  // clear phy first byte
  phy[0] = '\0';

  nl80211_request(iw, ifname, NL80211_CMD_GET_WIPHY, 0, nl80211_phyname_cb,
                  phy);

  return phy[0] ? phy : NULL;
}

static char *nl80211_phyidx2name(iwinfo_t *iw, char *phy, unsigned int idx) {
  if (iw == NULL)
    return NULL;
  struct nl80211_msg_conveyor *cv;

  // clear phy first byte
  phy[0] = '\0';

  cv = nl80211_new(iw, iw->state.nl80211, NL80211_CMD_GET_WIPHY, 0);
  if (!cv)
    return NULL;

  NLA_PUT_U32(cv->msg, NL80211_ATTR_WIPHY, idx);

  nl80211_send(iw, nl80211_phyname_cb, phy);

  return phy[0] ? phy : NULL;

nla_put_failure:
  nl80211_free(cv);
  return NULL;
}

static int nl80211_phy2ifnames(iwinfo_t *iw, const char *phy,
                               char (*ifnames)[IFNAMSIZ], int max) {
  if (iw == NULL || !phy)
    return 0;
  int count = 0, phyidx;
  char buffer[512];
  DIR *d;
  struct dirent *e;

  phyidx = nl80211_phy_idx_from_phy(phy);
  if (phyidx < 0)
    return 0;

  if ((d = opendir("/sys/class/net")) != NULL) {
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] == '.')
        continue;
      snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/phy80211/index",
               e->d_name);
      if (nl80211_readint(buffer) != phyidx)
        continue;

      if (count < max) {
        strncpy(ifnames[count], e->d_name, IFNAMSIZ - 1);
        ifnames[count][IFNAMSIZ - 1] = '\0';
        count++;
      }
    }
    closedir(d);
  }
  return count;
}

static char *nl80211_phy2ifname(iwinfo_t *iw, char *ifname, const char *phy) {
  if (iw == NULL)
    return NULL;
  int ifidx = -1, cifidx, lmode = 1, clmode, phyidx;
  char buffer[512];
  DIR *d;
  struct dirent *e;

  // clear ifname first byte
  ifname[0] = '\0';

  /* Only accept phy name in the form of phy%d or radio%d */
  if (!phy)
    return NULL;

  phyidx = nl80211_phy_idx_from_phy(phy);
  if (phyidx < 0)
    return NULL;

  if ((d = opendir("/sys/class/net")) != NULL) {
    while ((e = readdir(d)) != NULL) {
      snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/phy80211/index",
               e->d_name);
      if (nl80211_readint(buffer) != phyidx)
        continue;

      snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/ifindex", e->d_name);
      cifidx = nl80211_readint(buffer);

      if (cifidx < 0)
        continue;

      snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/link_mode",
               e->d_name);
      clmode = nl80211_readint(buffer);

      /* prefer non-supplicant-based devices */
      if ((ifidx < 0) || (cifidx < ifidx) || ((lmode == 1) && (clmode != 1))) {
        ifidx = cifidx;
        lmode = clmode;
        strncpy(ifname, e->d_name, IFNAMSIZ - 1);
      }
    }

    closedir(d);
  }

  return ifname[0] ? ifname : NULL;
}

static int nl80211_get_mode_cb(struct nl_msg *msg, void *arg) {
  int *mode = arg;
  struct nlattr **tb = nl80211_parse(msg);
  const int ifmodes[NL80211_IFTYPE_MAX + 1] = {
      IWINFO_OPMODE_UNKNOWN,    /* unspecified */
      IWINFO_OPMODE_ADHOC,      /* IBSS */
      IWINFO_OPMODE_CLIENT,     /* managed */
      IWINFO_OPMODE_MASTER,     /* AP */
      IWINFO_OPMODE_AP_VLAN,    /* AP/VLAN */
      IWINFO_OPMODE_WDS,        /* WDS */
      IWINFO_OPMODE_MONITOR,    /* monitor */
      IWINFO_OPMODE_MESHPOINT,  /* mesh point */
      IWINFO_OPMODE_P2P_CLIENT, /* P2P-client */
      IWINFO_OPMODE_P2P_GO,     /* P2P-GO */
  };

  if (tb[NL80211_ATTR_IFTYPE])
    *mode = ifmodes[nla_get_u32_safe(tb[NL80211_ATTR_IFTYPE])];

  return NL_SKIP;
}

static int nl80211_get_mode(iwinfo_t *iw, const char *ifname, int *buf) {

  *buf = IWINFO_OPMODE_UNKNOWN;

  nl80211_request(iw, ifname, NL80211_CMD_GET_INTERFACE, 0, nl80211_get_mode_cb,
                  buf);

  return (*buf == IWINFO_OPMODE_UNKNOWN) ? -1 : 0;
}

static int __nl80211_hostapd_query(iwinfo_t *iw, const char *ifname, ...) {
  va_list ap, ap_cur;
  char *phy, *search, *dest, *key, *val, buf[128];
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';
  int len, mode, found = 0, match = 1;
  FILE *fp;

  if (nl80211_get_mode(iw, ifname, &mode))
    return 0;

  if (mode != IWINFO_OPMODE_MASTER && mode != IWINFO_OPMODE_AP_VLAN)
    return 0;

  phy = nl80211_ifname2phy(iw, phybuf, ifname);

  if (!phy)
    return 0;

  snprintf(buf, sizeof(buf), "/var/run/hostapd-%s.conf", phy);
  fp = fopen(buf, "r");

  if (!fp)
    return 0;

  va_start(ap, ifname);

  /* clear all destination buffers */
  va_copy(ap_cur, ap);

  while ((search = va_arg(ap_cur, char *)) != NULL) {
    dest = va_arg(ap_cur, char *);
    len = va_arg(ap_cur, int);

    memset(dest, 0, len);
  }

  va_end(ap_cur);

  /* iterate applicable lines and copy found values into dest buffers */
  while (fgets(buf, sizeof(buf), fp)) {
    key = strtok(buf, " =\t\n");
    val = strtok(NULL, "\n");

    if (!key || !val || !*key || *key == '#')
      continue;

    if (!strcmp(key, "interface") || !strcmp(key, "bss"))
      match = !strcmp(ifname, val);

    if (!match)
      continue;

    va_copy(ap_cur, ap);

    while ((search = va_arg(ap_cur, char *)) != NULL) {
      dest = va_arg(ap_cur, char *);
      len = va_arg(ap_cur, int);

      if (!strcmp(search, key)) {
        strncpy(dest, val, len - 1);
        found++;
        break;
      }
    }

    va_end(ap_cur);
  }

  fclose(fp);

  va_end(ap);

  return found;
}

#define nl80211_hostapd_query(container, ifname, ...)                          \
  __nl80211_hostapd_query(container, ifname, ##__VA_ARGS__, NULL)

static inline int nl80211_wpactl_recv(int sock, char *buf, int blen) {
  fd_set rfds;
  struct timeval tv = {0, 256000};

  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);

  memset(buf, 0, blen);

  if (select(sock + 1, &rfds, NULL, NULL, &tv) < 0)
    return -1;

  if (!FD_ISSET(sock, &rfds))
    return -1;

  return recv(sock, buf, blen - 1, 0);
}

static int nl80211_wpactl_connect(const char *ifname,
                                  struct sockaddr_un *local) {
  struct sockaddr_un remote = {0};
  size_t remote_length, local_length;

  int sock = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0)
    return sock;

  remote.sun_family = AF_UNIX;
  remote_length =
      sizeof(remote.sun_family) +
      sprintf(remote.sun_path, "/var/run/wpa_supplicant/%s", ifname);

  /* Set client socket file permissions so that bind() creates the client
   * socket with these permissions and there is no need to try to change
   * them with chmod() after bind() which would have potential issues with
   * race conditions. These permissions are needed to make sure the server
   * side (wpa_supplicant or hostapd) can reply to the control interface
   * messages.
   *
   * The lchown() calls below after bind() are also part of the needed
   * operations to allow the response to go through. Those are using the
   * no-deference-symlinks version to avoid races. */
  fchmod(sock, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC) < 0) {
    close(sock);
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&remote, remote_length)) {
    close(sock);
    return -1;
  }

  local->sun_family = AF_UNIX;
  local_length =
      sizeof(local->sun_family) +
      sprintf(local->sun_path, "/var/run/iwinfo-%s-%d", ifname, getpid());

  if (bind(sock, (struct sockaddr *)local, local_length) < 0) {
    close(sock);
    return -1;
  }

  /* Set group even if we do not have privileges to change owner */
  lchown(local->sun_path, -1, 101);
  lchown(local->sun_path, 101, 101);

  return sock;
}

static int __nl80211_wpactl_query(iwinfo_t *iw, const char *ifname, ...) {
  va_list ap, ap_cur;
  struct sockaddr_un local = {0};
  int len, mode, found = 0, sock = -1;
  char *search, *dest, *key, *val, *line, *pos, buf[512];

  if (nl80211_get_mode(iw, ifname, &mode))
    return 0;

  if (mode != IWINFO_OPMODE_CLIENT && mode != IWINFO_OPMODE_ADHOC &&
      mode != IWINFO_OPMODE_MESHPOINT)
    return 0;

  sock = nl80211_wpactl_connect(ifname, &local);

  if (sock < 0)
    return 0;

  va_start(ap, ifname);

  /* clear all destination buffers */
  va_copy(ap_cur, ap);

  while ((search = va_arg(ap_cur, char *)) != NULL) {
    dest = va_arg(ap_cur, char *);
    len = va_arg(ap_cur, int);

    memset(dest, 0, len);
  }

  va_end(ap_cur);

  send(sock, "STATUS", 6, 0);

  while (true) {
    if (nl80211_wpactl_recv(sock, buf, sizeof(buf)) <= 0)
      break;

    if (buf[0] == '<')
      continue;

    for (line = strtok_r(buf, "\n", &pos); line != NULL;
         line = strtok_r(NULL, "\n", &pos)) {
      key = strtok(line, "=");
      val = strtok(NULL, "\n");

      if (!key || !val)
        continue;

      va_copy(ap_cur, ap);

      while ((search = va_arg(ap_cur, char *)) != NULL) {
        dest = va_arg(ap_cur, char *);
        len = va_arg(ap_cur, int);

        if (!strcmp(search, key)) {
          strncpy(dest, val, len - 1);
          found++;
          break;
        }
      }

      va_end(ap_cur);
    }

    break;
  }

  va_end(ap);

  close(sock);
  unlink(local.sun_path);

  return found;
}

#define nl80211_wpactl_query(container, ifname, ...)                           \
  __nl80211_wpactl_query(container, ifname, ##__VA_ARGS__, NULL)

static char *nl80211_ifadd(iwinfo_t *iw, char *nif, const char *ifname) {
  char path[PATH_MAX];

  // clear dst network interface first byte
  nif[0] = '\0';

  struct nl80211_msg_conveyor *req;
  FILE *sysfs;

  req = nl80211_msg(iw, ifname, NL80211_CMD_NEW_INTERFACE, 0);
  if (req) {
    snprintf(nif, IFNAMSIZ, "tmp.%s", ifname);

    NLA_PUT_STRING(req->msg, NL80211_ATTR_IFNAME, nif);
    NLA_PUT_U32(req->msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);

    nl80211_send(iw, NULL, NULL);

    snprintf(path, sizeof(path) - 1, "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
             nif);

    if ((sysfs = fopen(path, "w")) != NULL) {
      fwrite("0\n", 1, 2, sysfs);
      fclose(sysfs);
    }

    return nif;

  nla_put_failure:
    nl80211_free(req);
  }

  return NULL;
}

static void nl80211_ifdel(iwinfo_t *iw, const char *ifname) {
  struct nl80211_msg_conveyor *req;

  req = nl80211_msg(iw, ifname, NL80211_CMD_DEL_INTERFACE, 0);
  if (req) {
    NLA_PUT_STRING(req->msg, NL80211_ATTR_IFNAME, ifname);

    nl80211_send(iw, NULL, NULL);
    return;

  nla_put_failure:
    nl80211_free(req);
  }
}

static void nl80211_hostapd_hup(iwinfo_t *iw, const char *ifname) {
  int fd, pid = 0;
  char buf[64];
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';

  char *phy = nl80211_ifname2phy(iw, phybuf, ifname);

  if (phy) {
    snprintf(buf, sizeof(buf), "/var/run/wifi-%s.pid", phy);
    if ((fd = open(buf, O_RDONLY)) >= 0) {
      if (read(fd, buf, sizeof(buf)) > 0)
        pid = atoi(buf);

      close(fd);
    }

    if (pid > 0)
      kill(pid, 1);
  }
}

static int nl80211_probe(iwinfo_t *iw, const char *ifname) {
  int ret;
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';
  ret = !!nl80211_ifname2phy(iw, phybuf, ifname);
  if (ret)
    return ret;
  ret = nl80211_phy_idx_from_phy(ifname);
  if (ret < 0)
    return 0;
  return 1;
}

struct nl80211_ssid_bssid {
  unsigned char *ssid;
  unsigned char bssid[7];
};

static int nl80211_get_macaddr_cb(struct nl_msg *msg, void *arg) {
  struct nl80211_ssid_bssid *sb = arg;
  struct nlattr **tb = nl80211_parse(msg);

  if (tb[NL80211_ATTR_MAC]) {
    sb->bssid[0] = 1;
    memcpy(sb->bssid + 1, nla_data(tb[NL80211_ATTR_MAC]),
           sizeof(sb->bssid) - 1);
  }

  if (sb->ssid && tb[NL80211_ATTR_MESH_ID]) {
    memcpy(sb->ssid, nla_data(tb[NL80211_ATTR_MESH_ID]),
           min(nla_len(tb[NL80211_ATTR_MESH_ID]), IWINFO_ESSID_MAX_SIZE));
  }

  return NL_SKIP;
}

static int nl80211_get_ssid_bssid_cb(struct nl_msg *msg, void *arg) {
  int ielen;
  unsigned char *ie;
  struct nl80211_ssid_bssid *sb = arg;
  struct nlattr **tb = nl80211_parse(msg);
  struct nlattr *bss[NL80211_BSS_MAX + 1];

  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
      [NL80211_BSS_INFORMATION_ELEMENTS] = {0},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
  };

  if (!tb[NL80211_ATTR_BSS] ||
      nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy) ||
      !bss[NL80211_BSS_BSSID] || !bss[NL80211_BSS_STATUS] ||
      !bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
    return NL_SKIP;
  }

  switch (nla_get_u32_safe(bss[NL80211_BSS_STATUS])) {
  case NL80211_BSS_STATUS_ASSOCIATED:
  case NL80211_BSS_STATUS_AUTHENTICATED:
  case NL80211_BSS_STATUS_IBSS_JOINED:

    if (sb->ssid) {
      ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
      ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);

      while (ielen >= 2 && ielen >= ie[1]) {
        if (ie[0] == 0) {
          memcpy(sb->ssid, ie + 2, min(ie[1], IWINFO_ESSID_MAX_SIZE));
          return NL_SKIP;
        }

        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
      }
    } else {
      sb->bssid[0] = 1;
      memcpy(sb->bssid + 1, nla_data(bss[NL80211_BSS_BSSID]), 6);
      return NL_SKIP;
    }

  default:
    return NL_SKIP;
  }
}

static char *get_parent_ifname(const char *ifname) {
  char *dot = strchr(ifname, '.');
  if (!dot)
    return NULL;

  static char parent[IFNAMSIZ];
  size_t len = dot - ifname;
  if (len >= IFNAMSIZ)
    return NULL;

  strncpy(parent, ifname, len);
  parent[len] = '\0';
  return parent;
}

static int nl80211_get_ssid(iwinfo_t *iw, const char *ifname, char *buf) {
  char *res;
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';
  struct nl80211_ssid_bssid sb = {.ssid = (unsigned char *)buf};

  /* try to find ssid from scan dump results */
  res = nl80211_phy2ifname(iw, resbuf, ifname);
  sb.ssid[0] = 0;

  nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                  nl80211_get_ssid_bssid_cb, &sb);

  /* If SSID not found and interface name contains .<vlan_id>, try parent
   * interface */
  if (sb.ssid[0] == 0) {
    char *parent_if = get_parent_ifname(ifname);
    if (parent_if) {
      nl80211_request(iw, parent_if, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                      nl80211_get_ssid_bssid_cb, &sb);
    }
  }

  /* failed, try to find from hostapd info */
  if (sb.ssid[0] == 0) {
    nl80211_hostapd_query(iw, ifname, "ssid", sb.ssid,
                          IWINFO_ESSID_MAX_SIZE + 1);

    /* If still no SSID and we have VLAN, try parent interface with hostapd */
    if (sb.ssid[0] == 0) {
      char *parent_if = get_parent_ifname(ifname);
      if (parent_if) {
        nl80211_hostapd_query(iw, parent_if, "ssid", sb.ssid,
                              IWINFO_ESSID_MAX_SIZE + 1);
      }
    }
  }

  /* failed, try to obtain Mesh ID from interface info */
  if (sb.ssid[0] == 0)
    nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                    nl80211_get_macaddr_cb, &sb);

  return (sb.ssid[0] == 0) ? -1 : 0;
}

static int nl80211_get_bssid(iwinfo_t *iw, const char *ifname, char *buf) {
  char *res, bssid[sizeof("FF:FF:FF:FF:FF:FF\0")];
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';
  struct nl80211_ssid_bssid sb = {};

  res = nl80211_phy2ifname(iw, resbuf, ifname);

  /* try to obtain mac address via NL80211_CMD_GET_INTERFACE */
  nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                  nl80211_get_macaddr_cb, &sb);

  /* failed, try to find bssid from scan dump results */
  if (sb.bssid[0] == 0)
    nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                    nl80211_get_ssid_bssid_cb, &sb);

  /* failed, try to find mac from hostapd info */
  if ((sb.bssid[0] == 0) &&
      nl80211_hostapd_query(iw, ifname, "bssid", bssid, sizeof(bssid))) {
    sb.bssid[0] = 1;
    sb.bssid[1] = strtol(&bssid[0], NULL, 16);
    sb.bssid[2] = strtol(&bssid[3], NULL, 16);
    sb.bssid[3] = strtol(&bssid[6], NULL, 16);
    sb.bssid[4] = strtol(&bssid[9], NULL, 16);
    sb.bssid[5] = strtol(&bssid[12], NULL, 16);
    sb.bssid[6] = strtol(&bssid[15], NULL, 16);
  }

  if (sb.bssid[0]) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", sb.bssid[1], sb.bssid[2],
            sb.bssid[3], sb.bssid[4], sb.bssid[5], sb.bssid[6]);

    return 0;
  }

  return -1;
}

static int nl80211_get_frequency_scan_cb(struct nl_msg *msg, void *arg) {
  int *freq = arg;
  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *binfo[NL80211_BSS_MAX + 1];

  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
      [NL80211_BSS_FREQUENCY] = {.type = NLA_U32},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
  };

  if (attr[NL80211_ATTR_BSS] &&
      !nla_parse_nested(binfo, NL80211_BSS_MAX, attr[NL80211_ATTR_BSS],
                        bss_policy)) {
    if (binfo[NL80211_BSS_STATUS] && binfo[NL80211_BSS_FREQUENCY])
      *freq = nla_get_u32_safe(binfo[NL80211_BSS_FREQUENCY]);
  }

  return NL_SKIP;
}

static int nl80211_get_frequency_info_cb(struct nl_msg *msg, void *arg) {
  int *freq = arg;
  struct nlattr **tb = nl80211_parse(msg);

  if (tb[NL80211_ATTR_WIPHY_FREQ])
    *freq = nla_get_u32_safe(tb[NL80211_ATTR_WIPHY_FREQ]);

  return NL_SKIP;
}

static int nl80211_get_frequency(iwinfo_t *iw, const char *ifname, int *buf) {
  char *res, channel[4] = {0}, hwmode[3] = {0}, ax[2] = {0};
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';

  /* try to find frequency from interface info */
  res = nl80211_phy2ifname(iw, resbuf, ifname);
  *buf = 0;

  nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                  nl80211_get_frequency_info_cb, buf);

  /* failed, try to find frequency from hostapd info */
  if ((*buf == 0) &&
      nl80211_hostapd_query(iw, ifname, "hw_mode", hwmode, sizeof(hwmode),
                            "channel", channel, sizeof(channel), "ieee80211ax",
                            ax, sizeof(ax)) >= 2) {
    *buf = nl80211_channel2freq(atoi(channel), hwmode, ax[0] == '1');
  }

  /* failed, try to find frequency from scan results */
  if (*buf == 0) {
    res = nl80211_phy2ifname(iw, resbuf, ifname);

    nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                    nl80211_get_frequency_scan_cb, buf);
  }

  return (*buf == 0) ? -1 : 0;
}

static int nl80211_get_center_freq1_cb(struct nl_msg *msg, void *arg) {
  int *freq = arg;
  struct nlattr **tb = nl80211_parse(msg);

  if (tb[NL80211_ATTR_CENTER_FREQ1])
    *freq = nla_get_u32_safe(tb[NL80211_ATTR_CENTER_FREQ1]);

  return NL_SKIP;
}

static int nl80211_get_center_freq1(iwinfo_t *iw, const char *ifname,
                                    int *buf) {
  char *res;
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';

  /* try to find frequency from interface info */
  res = nl80211_phy2ifname(iw, resbuf, ifname);
  *buf = 0;

  nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                  nl80211_get_center_freq1_cb, buf);

  return (*buf == 0) ? -1 : 0;
}

static int nl80211_get_center_freq2_cb(struct nl_msg *msg, void *arg) {
  int *freq = arg;
  struct nlattr **tb = nl80211_parse(msg);

  if (tb[NL80211_ATTR_CENTER_FREQ2])
    *freq = nla_get_u32_safe(tb[NL80211_ATTR_CENTER_FREQ2]);

  return NL_SKIP;
}

static int nl80211_get_center_freq2(iwinfo_t *iw, const char *ifname,
                                    int *buf) {
  char *res;
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';

  /* try to find frequency from interface info */
  res = nl80211_phy2ifname(iw, resbuf, ifname);
  *buf = 0;

  nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                  nl80211_get_center_freq2_cb, buf);

  return (*buf == 0) ? -1 : 0;
}

static int nl80211_get_channel(iwinfo_t *iw, const char *ifname, int *buf) {
  if (!nl80211_get_frequency(iw, ifname, buf)) {
    *buf = nl80211_freq2channel(*buf);
    return 0;
  }

  return -1;
}

static int nl80211_get_center_chan1(iwinfo_t *iw, const char *ifname,
                                    int *buf) {
  if (!nl80211_get_center_freq1(iw, ifname, buf)) {
    *buf = nl80211_freq2channel(*buf);
    return 0;
  }

  return -1;
}

static int nl80211_get_center_chan2(iwinfo_t *iw, const char *ifname,
                                    int *buf) {
  if (!nl80211_get_center_freq2(iw, ifname, buf)) {
    *buf = nl80211_freq2channel(*buf);
    return 0;
  }

  return -1;
}

static int nl80211_get_txpower_cb(struct nl_msg *msg, void *arg) {
  int *buf = arg;
  struct nlattr **tb = nl80211_parse(msg);

  if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
    *buf =
        iwinfo_mbm2dbm(nla_get_u32_safe(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]));

  return NL_SKIP;
}

static int nl80211_get_txpower(iwinfo_t *iw, const char *ifname, int *buf) {
  char *res;
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';

  res = nl80211_phy2ifname(iw, resbuf, ifname);
  *buf = 0;

  if (nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                      nl80211_get_txpower_cb, buf))
    return -1;

  return 0;
}

static int nl80211_fill_signal_cb(struct nl_msg *msg, void *arg) {
  int8_t dbm;
  int16_t mbit;
  struct nl80211_rssi_rate *rr = arg;
  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];

  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
      [NL80211_STA_INFO_INACTIVE_TIME] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_BYTES] = {.type = NLA_U32},
      [NL80211_STA_INFO_TX_BYTES] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_BYTES64] = {.type = NLA_U64},
      [NL80211_STA_INFO_TX_BYTES64] = {.type = NLA_U64},
      [NL80211_STA_INFO_RX_PACKETS] = {.type = NLA_U32},
      [NL80211_STA_INFO_TX_PACKETS] = {.type = NLA_U32},
      [NL80211_STA_INFO_SIGNAL] = {.type = NLA_U8},
      [NL80211_STA_INFO_TX_BITRATE] = {.type = NLA_NESTED},
      [NL80211_STA_INFO_LLID] = {.type = NLA_U16},
      [NL80211_STA_INFO_PLID] = {.type = NLA_U16},
      [NL80211_STA_INFO_PLINK_STATE] = {.type = NLA_U8},
      [NL80211_STA_INFO_TX_DURATION] = {.type = NLA_U64},
      [NL80211_STA_INFO_RX_DURATION] = {.type = NLA_U64},
      [NL80211_STA_INFO_AIRTIME_WEIGHT] = {.type = NLA_U16},
  };

  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
      [NL80211_RATE_INFO_BITRATE] = {.type = NLA_U16},
      [NL80211_RATE_INFO_MCS] = {.type = NLA_U8},
      [NL80211_RATE_INFO_40_MHZ_WIDTH] = {.type = NLA_FLAG},
      [NL80211_RATE_INFO_SHORT_GI] = {.type = NLA_FLAG},
  };

  if (attr[NL80211_ATTR_STA_INFO]) {
    if (!nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                          attr[NL80211_ATTR_STA_INFO], stats_policy)) {
      if (sinfo[NL80211_STA_INFO_SIGNAL]) {
        dbm = nla_get_u8_safe(sinfo[NL80211_STA_INFO_SIGNAL]);
        rr->rssi = (rr->rssi * rr->rssi_samples + dbm) / (rr->rssi_samples + 1);
        rr->rssi_samples++;
      }

      if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
        if (!nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
                              sinfo[NL80211_STA_INFO_TX_BITRATE],
                              rate_policy)) {
          if (rinfo[NL80211_RATE_INFO_BITRATE]) {
            mbit = nla_get_u16_safe(rinfo[NL80211_RATE_INFO_BITRATE]);
            rr->rate =
                (rr->rate * rr->rate_samples + mbit) / (rr->rate_samples + 1);
            rr->rate_samples++;
          }
        }
      }
    }
  }

  return NL_SKIP;
}

static void nl80211_fill_signal(iwinfo_t *iw, const char *ifname,
                                struct nl80211_rssi_rate *r) {
  DIR *d;
  struct dirent *de;

  memset(r, 0, sizeof(*r));

  if ((d = opendir("/sys/class/net")) != NULL) {
    while ((de = readdir(d)) != NULL) {
      if (!strncmp(de->d_name, ifname, strlen(ifname)) &&
          (!de->d_name[strlen(ifname)] ||
           !strncmp(&de->d_name[strlen(ifname)], ".sta", 4))) {
        nl80211_request(iw, de->d_name, NL80211_CMD_GET_STATION, NLM_F_DUMP,
                        nl80211_fill_signal_cb, r);
      }
    }

    closedir(d);
  }
}

static int nl80211_get_bitrate(iwinfo_t *iw, const char *ifname, int *buf) {
  struct nl80211_rssi_rate rr;

  nl80211_fill_signal(iw, ifname, &rr);

  if (rr.rate_samples) {
    *buf = (rr.rate * 100);
    return 0;
  }

  return -1;
}

static int nl80211_get_signal(iwinfo_t *iw, const char *ifname, int *buf) {
  struct nl80211_rssi_rate rr;

  nl80211_fill_signal(iw, ifname, &rr);

  if (rr.rssi_samples) {
    *buf = rr.rssi;
    return 0;
  }

  return -1;
}

static int nl80211_get_noise_cb(struct nl_msg *msg, void *arg) {
  int8_t *noise = arg;
  struct nlattr **tb = nl80211_parse(msg);
  struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];

  static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
      [NL80211_SURVEY_INFO_FREQUENCY] = {.type = NLA_U32},
      [NL80211_SURVEY_INFO_NOISE] = {.type = NLA_U8},
  };

  if (!tb[NL80211_ATTR_SURVEY_INFO])
    return NL_SKIP;

  if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
                       tb[NL80211_ATTR_SURVEY_INFO], sp))
    return NL_SKIP;

  if (!si[NL80211_SURVEY_INFO_NOISE])
    return NL_SKIP;

  if (!*noise || si[NL80211_SURVEY_INFO_IN_USE])
    *noise = (int8_t)nla_get_u8_safe(si[NL80211_SURVEY_INFO_NOISE]);

  return NL_SKIP;
}

static int nl80211_get_noise(iwinfo_t *iw, const char *ifname, int *buf) {
  int8_t noise = 0;

  if (nl80211_request(iw, ifname, NL80211_CMD_GET_SURVEY, NLM_F_DUMP,
                      nl80211_get_noise_cb, &noise))
    goto out;

  *buf = noise;
  return 0;

out:
  *buf = 0;
  return -1;
}

static int nl80211_get_quality(iwinfo_t *iw, const char *ifname, int *buf) {
  int signal;

  if (!nl80211_get_signal(iw, ifname, &signal)) {
    /* A positive signal level is usually just a quality
     * value, pass through as-is */
    if (signal >= 0) {
      *buf = signal;
    }

    /* The cfg80211 wext compat layer assumes a signal range
     * of -110 dBm to -40 dBm, the quality value is derived
     * by adding 110 to the signal level */
    else {
      if (signal < -110)
        signal = -110;
      else if (signal > -40)
        signal = -40;

      *buf = (signal + 110);
    }

    return 0;
  }

  return -1;
}

static int nl80211_get_quality_max(iwinfo_t *iw, const char *ifname, int *buf) {
  /* The cfg80211 wext compat layer assumes a maximum
   * quality of 70 */
  *buf = 70;

  return 0;
}

static int nl80211_check_wepkey(const char *key) {
  if (key && *key) {
    switch (strlen(key)) {
    case 5:
    case 10:
      return IWINFO_CIPHER_WEP40;

    case 13:
    case 26:
      return IWINFO_CIPHER_WEP104;
    }
  }

  return 0;
}

static const struct {
  const char *match;
  int version;
  int suite;
} wpa_key_mgmt_strings[] = {{"IEEE 802.1X/EAP", 0, IWINFO_KMGMT_8021x},
                            {"EAP-SUITE-B-192", 4, IWINFO_KMGMT_8021x},
                            {"EAP-SUITE-B", 4, IWINFO_KMGMT_8021x},
                            {"EAP-SHA384", 4, IWINFO_KMGMT_8021x},
                            {"EAP-SHA256", 0, IWINFO_KMGMT_8021x},
                            {"PSK-SHA256", 0, IWINFO_KMGMT_PSK},
                            {"NONE", 0, IWINFO_KMGMT_NONE},
                            {"None", 0, IWINFO_KMGMT_NONE},
                            {"PSK", 0, IWINFO_KMGMT_PSK},
                            {"EAP", 0, IWINFO_KMGMT_8021x},
                            {"SAE", 4, IWINFO_KMGMT_SAE},
                            {"OWE", 4, IWINFO_KMGMT_OWE}};

static void parse_wpa_suites(const char *str, int defversion, uint8_t *versions,
                             uint8_t *suites) {
  size_t l;
  int i, version;
  const char *p, *q, *m, *sep = " \t\n,-+/";

  for (p = str; *p;) {
    q = p;

    for (i = 0; i < ARRAY_SIZE(wpa_key_mgmt_strings); i++) {
      m = wpa_key_mgmt_strings[i].match;
      l = strlen(m);

      if (!strncmp(q, m, l) && (!q[l] || strchr(sep, q[l]))) {
        if (wpa_key_mgmt_strings[i].version != 0)
          version = wpa_key_mgmt_strings[i].version;
        else
          version = defversion;

        *versions |= version;
        *suites |= wpa_key_mgmt_strings[i].suite;

        q += l;
        break;
      }
    }

    if (q == p)
      q += strcspn(q, sep);

    p = q + strspn(q, sep);
  }
}

static const struct {
  const char *match;
  int cipher;
} wpa_cipher_strings[] = {
    {"WEP-104", IWINFO_CIPHER_WEP104},   {"WEP-40", IWINFO_CIPHER_WEP40},
    {"NONE", IWINFO_CIPHER_NONE},        {"TKIP", IWINFO_CIPHER_TKIP},
    {"CCMP-256", IWINFO_CIPHER_CCMP256}, {"CCMP", IWINFO_CIPHER_CCMP},
    {"GCMP-256", IWINFO_CIPHER_GCMP256}, {"GCMP", IWINFO_CIPHER_GCMP}};

static void parse_wpa_ciphers(const char *str, uint16_t *ciphers) {
  int i;
  size_t l;
  const char *m, *p, *q, *sep = " \t\n,-+/";

  for (p = str; *p;) {
    q = p;

    for (i = 0; i < ARRAY_SIZE(wpa_cipher_strings); i++) {
      m = wpa_cipher_strings[i].match;
      l = strlen(m);

      if (!strncmp(q, m, l) && (!q[l] || strchr(sep, q[l]))) {
        *ciphers |= wpa_cipher_strings[i].cipher;

        q += l;
        break;
      }
    }

    if (q == p)
      q += strcspn(q, sep);

    p = q + strspn(q, sep);
  }
}

static int nl80211_get_encryption(iwinfo_t *iw, const char *ifname, char *buf) {
  char *p;
  int opmode;
  uint8_t wpa_version = 0;
  char wpa[2], wpa_key_mgmt[64], wpa_pairwise[16], wpa_groupwise[16];
  char auth_algs[2], wep_key0[27], wep_key1[27], wep_key2[27], wep_key3[27];
  char mode[16];

  struct iwinfo_crypto_entry *c = (struct iwinfo_crypto_entry *)buf;

  /* WPA supplicant */
  if (nl80211_wpactl_query(iw, ifname, "pairwise_cipher", wpa_pairwise,
                           sizeof(wpa_pairwise), "group_cipher", wpa_groupwise,
                           sizeof(wpa_groupwise), "key_mgmt", wpa_key_mgmt,
                           sizeof(wpa_key_mgmt), "mode", mode, sizeof(mode))) {
    /* WEP or Open */
    if (!strcmp(wpa_key_mgmt, "NONE")) {
      parse_wpa_ciphers(wpa_pairwise, &c->pair_ciphers);
      parse_wpa_ciphers(wpa_groupwise, &c->group_ciphers);

      if (c->pair_ciphers != 0 && c->pair_ciphers != IWINFO_CIPHER_NONE) {
        c->enabled = 1;
        c->auth_suites = IWINFO_KMGMT_NONE;
        c->auth_algs = IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED;
      } else {
        c->pair_ciphers = 0;
        c->group_ciphers = 0;
      }
    }

    /* MESH with SAE */
    else if (!strcmp(mode, "mesh") && !strcmp(wpa_key_mgmt, "UNKNOWN")) {
      c->enabled = 1;
      c->wpa_version = 4;
      c->auth_suites = IWINFO_KMGMT_SAE;
      c->pair_ciphers = IWINFO_CIPHER_CCMP;
      c->group_ciphers = IWINFO_CIPHER_CCMP;
    }

    /* WPA */
    else {
      parse_wpa_ciphers(wpa_pairwise, &c->pair_ciphers);
      parse_wpa_ciphers(wpa_groupwise, &c->group_ciphers);

      p = wpa_key_mgmt;

      if (!strncmp(p, "WPA2-", 5) || !strncmp(p, "WPA2/", 5)) {
        p += 5;
        wpa_version = 2;
      } else if (!strncmp(p, "WPA-", 4)) {
        p += 4;
        wpa_version = 1;
      }

      parse_wpa_suites(p, wpa_version, &c->wpa_version, &c->auth_suites);

      c->enabled = !!(c->wpa_version && c->auth_suites);
    }

    return 0;
  }

  /* Hostapd */
  else if (nl80211_hostapd_query(
               iw, ifname, "wpa", wpa, sizeof(wpa), "wpa_key_mgmt",
               wpa_key_mgmt, sizeof(wpa_key_mgmt), "wpa_pairwise", wpa_pairwise,
               sizeof(wpa_pairwise), "auth_algs", auth_algs, sizeof(auth_algs),
               "wep_key0", wep_key0, sizeof(wep_key0), "wep_key1", wep_key1,
               sizeof(wep_key1), "wep_key2", wep_key2, sizeof(wep_key2),
               "wep_key3", wep_key3, sizeof(wep_key3))) {
    c->wpa_version = 0;

    if (wpa_key_mgmt[0]) {
      for (p = strtok(wpa_key_mgmt, " \t"); p != NULL;
           p = strtok(NULL, " \t")) {
        if (!strncmp(p, "WPA-", 4))
          p += 4;

        if (!strncmp(p, "FT-", 3))
          p += 3;

        parse_wpa_suites(p, atoi(wpa), &c->wpa_version, &c->auth_suites);
      }

      c->enabled = c->wpa_version ? 1 : 0;
    }

    if (wpa_pairwise[0])
      parse_wpa_ciphers(wpa_pairwise, &c->pair_ciphers);

    if (auth_algs[0]) {
      switch (atoi(auth_algs)) {
      case 1:
        c->auth_algs |= IWINFO_AUTH_OPEN;
        break;

      case 2:
        c->auth_algs |= IWINFO_AUTH_SHARED;
        break;

      case 3:
        c->auth_algs |= IWINFO_AUTH_OPEN;
        c->auth_algs |= IWINFO_AUTH_SHARED;
        break;
      }

      c->pair_ciphers |= nl80211_check_wepkey(wep_key0);
      c->pair_ciphers |= nl80211_check_wepkey(wep_key1);
      c->pair_ciphers |= nl80211_check_wepkey(wep_key2);
      c->pair_ciphers |= nl80211_check_wepkey(wep_key3);

      c->enabled = (c->auth_algs && c->pair_ciphers) ? 1 : 0;
    }

    c->group_ciphers = c->pair_ciphers;

    return 0;
  }

  /* Ad-Hoc or Mesh interfaces without wpa_supplicant are open */
  else if (!nl80211_get_mode(iw, ifname, &opmode) &&
           (opmode == IWINFO_OPMODE_ADHOC ||
            opmode == IWINFO_OPMODE_MESHPOINT)) {
    c->enabled = 0;

    return 0;
  }

  return -1;
}

static int nl80211_get_phyname(iwinfo_t *iw, const char *ifname, char *buf) {
  const char *phy;
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';
  phy = nl80211_ifname2phy(iw, phybuf, ifname);

  if (phy) {
    strcpy(buf, phy);
    return 0;
  } else if ((phy = nl80211_phy2ifname(iw, phybuf, ifname)) != NULL) {
    phy = nl80211_ifname2phy(iw, phybuf, phy);

    if (phy) {
      strcpy(buf, phy);
      return 0;
    }
  }

  return -1;
}

static void nl80211_parse_rateinfo(struct nlattr **ri,
                                   struct iwinfo_rate_entry *re) {
  if (ri[NL80211_RATE_INFO_BITRATE32])
    re->rate = nla_get_u32_safe(ri[NL80211_RATE_INFO_BITRATE32]) * 100;
  else if (ri[NL80211_RATE_INFO_BITRATE])
    re->rate = nla_get_u16_safe(ri[NL80211_RATE_INFO_BITRATE]) * 100;

  if (ri[NL80211_RATE_INFO_HE_MCS]) {
    re->is_he = 1;
    re->mcs = nla_get_u8_safe(ri[NL80211_RATE_INFO_HE_MCS]);

    if (ri[NL80211_RATE_INFO_HE_NSS])
      re->nss = nla_get_u8_safe(ri[NL80211_RATE_INFO_HE_NSS]);
    if (ri[NL80211_RATE_INFO_HE_GI])
      re->he_gi = nla_get_u8_safe(ri[NL80211_RATE_INFO_HE_GI]);
    if (ri[NL80211_RATE_INFO_HE_DCM])
      re->he_dcm = nla_get_u8_safe(ri[NL80211_RATE_INFO_HE_DCM]);
  } else if (ri[NL80211_RATE_INFO_VHT_MCS]) {
    re->is_vht = 1;
    re->mcs = nla_get_u8_safe(ri[NL80211_RATE_INFO_VHT_MCS]);

    if (ri[NL80211_RATE_INFO_VHT_NSS])
      re->nss = nla_get_u8_safe(ri[NL80211_RATE_INFO_VHT_NSS]);
  } else if (ri[NL80211_RATE_INFO_MCS]) {
    re->is_ht = 1;
    re->mcs = nla_get_u8_safe(ri[NL80211_RATE_INFO_MCS]);
  }

  if (ri[NL80211_RATE_INFO_5_MHZ_WIDTH])
    re->mhz = 5;
  else if (ri[NL80211_RATE_INFO_10_MHZ_WIDTH])
    re->mhz = 10;
  else if (ri[NL80211_RATE_INFO_40_MHZ_WIDTH])
    re->mhz = 40;
  else if (ri[NL80211_RATE_INFO_80_MHZ_WIDTH])
    re->mhz = 80;
  else if (ri[NL80211_RATE_INFO_80P80_MHZ_WIDTH] ||
           ri[NL80211_RATE_INFO_160_MHZ_WIDTH])
    re->mhz = 160;
  else
    re->mhz = 20;

  if (ri[NL80211_RATE_INFO_SHORT_GI])
    re->is_short_gi = 1;

  re->is_40mhz = (re->mhz == 40);
}

static int nl80211_get_survey_cb(struct nl_msg *msg, void *arg) {
  NLA_DBG("%s:%d %s\n", __FILE__, __LINE__, __func__);

  if (!arg) {
    NLA_DBG("%s:%d arg=NULL\n", __FILE__, __LINE__);
    return NL_STOP;
  }

  struct nl80211_array_buf *arr = (struct nl80211_array_buf *)arg;

  if (!arr->buf) {
    NLA_DBG("%s:%d arr->buf=NULL\n", __FILE__, __LINE__);
    return NL_STOP;
  }

  if (arr->max_count == 0) {
    NLA_DBG("%s:%d arr->max_count==0\n", __FILE__, __LINE__);
    return NL_STOP;
  }

  if (arr->count >= arr->max_count) {
    NLA_DBG("%s:%d arr->count >= arr->max_count\n", __FILE__, __LINE__);
    return NL_STOP;
  }

  // prevent size_t overflow
  if ((SIZE_MAX / sizeof(struct iwinfo_survey_entry)) < arr->max_count) {
    NLA_DBG("%s:%d size overflow risk\n", __FILE__, __LINE__);
    return NL_STOP;
  }

  struct iwinfo_survey_entry *buf = arr->buf;
  char *buf_start = (char *)buf;
  char *buf_end = buf_start + (arr->max_count * sizeof(*buf));
  struct iwinfo_survey_entry *e = &buf[arr->count];
  char *e_ptr = (char *)e;

  if ((e_ptr + sizeof(*e)) > buf_end) {
    size_t overflow __attribute__((unused)) =
        (size_t)((e_ptr + sizeof(*e)) - buf_end);
    NLA_DBG("%s:%d buffer overflow=%zu risk e=%p end=%p\n", __FILE__, __LINE__,
            overflow, (void *)e, (void *)buf_end);
    return NL_STOP;
  }

  struct nlattr **attr = nl80211_parse(msg);
  // NLA_DBG("%s:%d after parse\n", __FILE__, __LINE__);
  if (!attr) {
    NLA_DBG("%s:%d attr=NULL\n", __FILE__, __LINE__);
    return NL_SKIP;
  }

  if (!attr[NL80211_ATTR_SURVEY_INFO]) {
    NLA_DBG("%s:%d attr[NL80211_ATTR_SURVEY_INFO]=NULL\n", __FILE__, __LINE__);
    return NL_SKIP;
  }

  struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
  static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
      [NL80211_SURVEY_INFO_FREQUENCY] = {.type = NLA_U32},
      [NL80211_SURVEY_INFO_NOISE] = {.type = NLA_U8},
      [NL80211_SURVEY_INFO_TIME] = {.type = NLA_U64},
      [NL80211_SURVEY_INFO_TIME_BUSY] = {.type = NLA_U64},
      [NL80211_SURVEY_INFO_TIME_EXT_BUSY] = {.type = NLA_U64},
      [NL80211_SURVEY_INFO_TIME_RX] = {.type = NLA_U64},
      [NL80211_SURVEY_INFO_TIME_TX] = {.type = NLA_U64},
  };

  int rc = nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                            attr[NL80211_ATTR_SURVEY_INFO], survey_policy);
  // NLA_DBG("%s:%d after nla_parse_nested rc=%d\n", __FILE__, __LINE__, rc);
  if (rc)
    return NL_SKIP;

  memset(e, 0, sizeof(*e));
  // NLA_DBG("%s:%d memset done\n", __FILE__, __LINE__);

  if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
    e->mhz = nla_get_u32_safe(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
  // NLA_DBG("NL80211_SURVEY_INFO_FREQUENCY ");

  if (sinfo[NL80211_SURVEY_INFO_NOISE])
    e->noise = (int8_t)nla_get_u8_safe(sinfo[NL80211_SURVEY_INFO_NOISE]);
  // NLA_DBG("NL80211_SURVEY_INFO_NOISE ");

  if (sinfo[NL80211_SURVEY_INFO_TIME])
    e->active_time = nla_get_u64_safe(sinfo[NL80211_SURVEY_INFO_TIME]);
  // NLA_DBG("NL80211_SURVEY_INFO_TIME ");

  if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
    e->busy_time = nla_get_u64_safe(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
  // NLA_DBG("NL80211_SURVEY_INFO_TIME_BUSY ");

  if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
    e->busy_time_ext =
        nla_get_u64_safe(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
  // NLA_DBG("NL80211_SURVEY_INFO_TIME_EXT_BUSY ");

  if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
    e->rxtime = nla_get_u64_safe(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
  // NLA_DBG("NL80211_SURVEY_INFO_TIME_RX ");

  if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
    e->txtime = nla_get_u64_safe(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
  // NLA_DBG("NL80211_SURVEY_INFO_TIME_TX ");

  // NLA_DBG("\n");
  arr->count++;
  NLA_DBG("%s:%d count++=%d\n", __FILE__, __LINE__, arr->count);
  return NL_SKIP;
}

static void plink_state_to_str(char *dst, unsigned state) {
  switch (state) {
  case NL80211_PLINK_LISTEN:
    strcpy(dst, "LISTEN");
    break;
  case NL80211_PLINK_OPN_SNT:
    strcpy(dst, "OPN_SNT");
    break;
  case NL80211_PLINK_OPN_RCVD:
    strcpy(dst, "OPN_RCVD");
    break;
  case NL80211_PLINK_CNF_RCVD:
    strcpy(dst, "CNF_RCVD");
    break;
  case NL80211_PLINK_ESTAB:
    strcpy(dst, "ESTAB");
    break;
  case NL80211_PLINK_HOLDING:
    strcpy(dst, "HOLDING");
    break;
  case NL80211_PLINK_BLOCKED:
    strcpy(dst, "BLOCKED");
    break;
  default:
    strcpy(dst, "UNKNOWN");
    break;
  }
}

static void power_mode_to_str(char *dst, struct nlattr *a) {
  enum nl80211_mesh_power_mode pm = nla_get_u32_safe(a);

  switch (pm) {
  case NL80211_MESH_POWER_ACTIVE:
    strcpy(dst, "ACTIVE");
    break;
  case NL80211_MESH_POWER_LIGHT_SLEEP:
    strcpy(dst, "LIGHT SLEEP");
    break;
  case NL80211_MESH_POWER_DEEP_SLEEP:
    strcpy(dst, "DEEP SLEEP");
    break;
  default:
    strcpy(dst, "UNKNOWN");
    break;
  }
}

static int nl80211_get_assoclist_cb(struct nl_msg *msg, void *arg) {
  struct nl80211_array_buf *arr = arg;
  struct iwinfo_assoclist_entry *e = arr->buf;
  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  struct nl80211_sta_flag_update *sta_flags;

  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
      [NL80211_STA_INFO_INACTIVE_TIME] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_PACKETS] = {.type = NLA_U32},
      [NL80211_STA_INFO_TX_PACKETS] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_BITRATE] = {.type = NLA_NESTED},
      [NL80211_STA_INFO_TX_BITRATE] = {.type = NLA_NESTED},
      [NL80211_STA_INFO_SIGNAL] = {.type = NLA_U8},
      [NL80211_STA_INFO_SIGNAL_AVG] = {.type = NLA_U8},
      [NL80211_STA_INFO_RX_BYTES] = {.type = NLA_U32},
      [NL80211_STA_INFO_TX_BYTES] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_BYTES64] = {.type = NLA_U64},
      [NL80211_STA_INFO_TX_BYTES64] = {.type = NLA_U64},
      [NL80211_STA_INFO_TX_RETRIES] = {.type = NLA_U32},
      [NL80211_STA_INFO_TX_FAILED] = {.type = NLA_U32},
      [NL80211_STA_INFO_CONNECTED_TIME] = {.type = NLA_U32},
      [NL80211_STA_INFO_RX_DROP_MISC] = {.type = NLA_U64},
      [NL80211_STA_INFO_T_OFFSET] = {.type = NLA_U64},
      [NL80211_STA_INFO_STA_FLAGS] = {.minlen = sizeof(
                                          struct nl80211_sta_flag_update)},
      [NL80211_STA_INFO_EXPECTED_THROUGHPUT] = {.type = NLA_U32},
      /* mesh */
      [NL80211_STA_INFO_LLID] = {.type = NLA_U16},
      [NL80211_STA_INFO_PLID] = {.type = NLA_U16},
      [NL80211_STA_INFO_PLINK_STATE] = {.type = NLA_U8},
      [NL80211_STA_INFO_LOCAL_PM] = {.type = NLA_U32},
      [NL80211_STA_INFO_PEER_PM] = {.type = NLA_U32},
      [NL80211_STA_INFO_NONPEER_PM] = {.type = NLA_U32},
  };

  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
      [NL80211_RATE_INFO_BITRATE] = {.type = NLA_U16},
      [NL80211_RATE_INFO_MCS] = {.type = NLA_U8},
      [NL80211_RATE_INFO_40_MHZ_WIDTH] = {.type = NLA_FLAG},
      [NL80211_RATE_INFO_SHORT_GI] = {.type = NLA_FLAG},
  };

  /* advance to end of array */
  e += arr->count;
  memset(e, 0, sizeof(*e));

  if (attr[NL80211_ATTR_MAC])
    memcpy(e->mac, nla_data(attr[NL80211_ATTR_MAC]), 6);

  if (attr[NL80211_ATTR_STA_INFO] &&
      !nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                        attr[NL80211_ATTR_STA_INFO], stats_policy)) {
    if (sinfo[NL80211_STA_INFO_SIGNAL])
      e->signal = nla_get_u8_safe(sinfo[NL80211_STA_INFO_SIGNAL]);

    if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
      e->signal_avg = nla_get_u8_safe(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

    if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
      e->inactive = nla_get_u32_safe(sinfo[NL80211_STA_INFO_INACTIVE_TIME]);

    if (sinfo[NL80211_STA_INFO_CONNECTED_TIME])
      e->connected_time =
          nla_get_u32_safe(sinfo[NL80211_STA_INFO_CONNECTED_TIME]);

    if (sinfo[NL80211_STA_INFO_RX_PACKETS])
      e->rx_packets = nla_get_u32_safe(sinfo[NL80211_STA_INFO_RX_PACKETS]);

    if (sinfo[NL80211_STA_INFO_TX_PACKETS])
      e->tx_packets = nla_get_u32_safe(sinfo[NL80211_STA_INFO_TX_PACKETS]);

    if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
        !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
                          sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy))
      nl80211_parse_rateinfo(rinfo, &e->rx_rate);

    if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
        !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
                          sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy))
      nl80211_parse_rateinfo(rinfo, &e->tx_rate);

    if (sinfo[NL80211_STA_INFO_RX_BYTES64])
      e->rx_bytes = nla_get_u64_safe(sinfo[NL80211_STA_INFO_RX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_RX_BYTES])
      e->rx_bytes = nla_get_u32_safe(sinfo[NL80211_STA_INFO_RX_BYTES]);

    if (sinfo[NL80211_STA_INFO_TX_BYTES64])
      e->tx_bytes = nla_get_u64_safe(sinfo[NL80211_STA_INFO_TX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_TX_BYTES])
      e->tx_bytes = nla_get_u32_safe(sinfo[NL80211_STA_INFO_TX_BYTES]);

    if (sinfo[NL80211_STA_INFO_TX_RETRIES])
      e->tx_retries = nla_get_u32_safe(sinfo[NL80211_STA_INFO_TX_RETRIES]);

    if (sinfo[NL80211_STA_INFO_TX_FAILED])
      e->tx_failed = nla_get_u32_safe(sinfo[NL80211_STA_INFO_TX_FAILED]);

    if (sinfo[NL80211_STA_INFO_T_OFFSET])
      e->t_offset = nla_get_u64_safe(sinfo[NL80211_STA_INFO_T_OFFSET]);

    if (sinfo[NL80211_STA_INFO_RX_DROP_MISC])
      e->rx_drop_misc = nla_get_u64_safe(sinfo[NL80211_STA_INFO_RX_DROP_MISC]);

    if (sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT])
      e->thr = nla_get_u32_safe(sinfo[NL80211_STA_INFO_EXPECTED_THROUGHPUT]);

    /* mesh */
    if (sinfo[NL80211_STA_INFO_LLID])
      e->llid = nla_get_u16_safe(sinfo[NL80211_STA_INFO_LLID]);

    if (sinfo[NL80211_STA_INFO_PLID])
      e->plid = nla_get_u16_safe(sinfo[NL80211_STA_INFO_PLID]);

    if (sinfo[NL80211_STA_INFO_PLINK_STATE])
      plink_state_to_str(e->plink_state,
                         nla_get_u8_safe(sinfo[NL80211_STA_INFO_PLINK_STATE]));

    if (sinfo[NL80211_STA_INFO_TX_DURATION])
      e->tx_duration = nla_get_u64_safe(sinfo[NL80211_STA_INFO_TX_DURATION]);

    if (sinfo[NL80211_STA_INFO_RX_DURATION])
      e->rx_duration = nla_get_u64_safe(sinfo[NL80211_STA_INFO_RX_DURATION]);

    if (sinfo[NL80211_STA_INFO_AIRTIME_WEIGHT])
      e->airtime_weight =
          nla_get_u16_safe(sinfo[NL80211_STA_INFO_AIRTIME_WEIGHT]);

    if (sinfo[NL80211_STA_INFO_LOCAL_PM])
      power_mode_to_str(e->local_ps, sinfo[NL80211_STA_INFO_LOCAL_PM]);
    if (sinfo[NL80211_STA_INFO_PEER_PM])
      power_mode_to_str(e->peer_ps, sinfo[NL80211_STA_INFO_PEER_PM]);
    if (sinfo[NL80211_STA_INFO_NONPEER_PM])
      power_mode_to_str(e->nonpeer_ps, sinfo[NL80211_STA_INFO_NONPEER_PM]);

    /* Station flags */
    if (sinfo[NL80211_STA_INFO_STA_FLAGS]) {
      sta_flags = (struct nl80211_sta_flag_update *)nla_data(
          sinfo[NL80211_STA_INFO_STA_FLAGS]);

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHORIZED) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_AUTHORIZED))
        e->is_authorized = 1;

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHENTICATED) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_AUTHENTICATED))
        e->is_authenticated = 1;

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_SHORT_PREAMBLE) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_SHORT_PREAMBLE))
        e->is_preamble_short = 1;

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_WME) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_WME))
        e->is_wme = 1;

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_MFP) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_MFP))
        e->is_mfp = 1;

      if (sta_flags->mask & BIT(NL80211_STA_FLAG_TDLS_PEER) &&
          sta_flags->set & BIT(NL80211_STA_FLAG_TDLS_PEER))
        e->is_tdls = 1;
    }
  }

  e->noise = 0; /* filled in by caller */
  arr->count++;

  return NL_SKIP;
}

static int nl80211_get_survey(iwinfo_t *iw, const char *ifname, char *buf,
                              int *len) {
  if (!len || *len == 0)
    return EINVAL;

  struct nl80211_array_buf arr = {
      .buf = buf,
      .count = 0,
      .max_count = *len / sizeof(struct iwinfo_survey_entry),
  };

  NLA_DBG("survey: request on %s, entry=%d max=%d entries\n", ifname, arr.count,
          arr.max_count);

  int rc = nl80211_request(iw, ifname, NL80211_CMD_GET_SURVEY, NLM_F_DUMP,
                           nl80211_get_survey_cb, &arr);

  if ((arr.count * sizeof(struct iwinfo_survey_entry)) > *len) {
    NLA_DBG("error: BUG: survey overflow detected: count=%u > max=%d\n",
            arr.count, *len / (int)sizeof(struct iwinfo_survey_entry));
    arr.count = *len / sizeof(struct iwinfo_survey_entry);
  }

  if (!rc && arr.count > 0)
    *len = arr.count * sizeof(struct iwinfo_survey_entry);
  else
    *len = 0;

  NLA_DBG("survey: collected %u entries\n", arr.count);

  return 0;
}

static int nl80211_get_assoclist(iwinfo_t *iw, const char *ifname, char *buf,
                                 int *len) {
  DIR *d;
  int i, noise = 0;
  struct dirent *de;
  struct nl80211_array_buf arr = {.buf = buf, .count = 0};
  struct iwinfo_assoclist_entry *e;

  if ((d = opendir("/sys/class/net")) != NULL) {
    while ((de = readdir(d)) != NULL) {
      if (!strncmp(de->d_name, ifname, strlen(ifname)) &&
          (!de->d_name[strlen(ifname)] ||
           !strncmp(&de->d_name[strlen(ifname)], ".sta", 4))) {
        nl80211_request(iw, de->d_name, NL80211_CMD_GET_STATION, NLM_F_DUMP,
                        nl80211_get_assoclist_cb, &arr);
      }
    }

    closedir(d);

    if (!nl80211_get_noise(iw, ifname, &noise))
      for (i = 0, e = arr.buf; i < arr.count; i++, e++)
        e->noise = noise;

    *len = (arr.count * sizeof(struct iwinfo_assoclist_entry));
    return 0;
  }

  return -1;
}

static int nl80211_get_txpwrlist_cb(struct nl_msg *msg, void *arg) {
  int *dbm_max = arg;
  int ch_cur, ch_cmp, bands_remain, freqs_remain;

  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *bands[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *freqs[NL80211_FREQUENCY_ATTR_MAX + 1];
  struct nlattr *band, *freq;

  static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
      [NL80211_FREQUENCY_ATTR_FREQ] = {.type = NLA_U32},
      [NL80211_FREQUENCY_ATTR_DISABLED] = {.type = NLA_FLAG},
      [NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = {.type = NLA_FLAG},
      [NL80211_FREQUENCY_ATTR_NO_IBSS] = {.type = NLA_FLAG},
      [NL80211_FREQUENCY_ATTR_RADAR] = {.type = NLA_FLAG},
      [NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = {.type = NLA_U32},
  };

  ch_cur = *dbm_max; /* value int* is initialized with channel by caller */
  *dbm_max = -1;

  nla_for_each_nested(band, attr[NL80211_ATTR_WIPHY_BANDS], bands_remain) {
    nla_parse(bands, NL80211_BAND_ATTR_MAX, nla_data(band), nla_len(band),
              NULL);

    nla_for_each_nested(freq, bands[NL80211_BAND_ATTR_FREQS], freqs_remain) {
      nla_parse(freqs, NL80211_FREQUENCY_ATTR_MAX, nla_data(freq),
                nla_len(freq), freq_policy);

      ch_cmp = nl80211_freq2channel(
          nla_get_u32_safe(freqs[NL80211_FREQUENCY_ATTR_FREQ]));

      if ((!ch_cur || (ch_cmp == ch_cur)) &&
          freqs[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) {
        *dbm_max =
            (int)(0.01 *
                  nla_get_u32_safe(freqs[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]));

        break;
      }
    }
  }

  return NL_SKIP;
}

static int nl80211_get_txpwrlist(iwinfo_t *iw, const char *ifname, char *buf,
                                 int *len) {
  int err, ch_cur;
  int dbm_max = -1, dbm_cur, dbm_cnt;
  struct iwinfo_txpwrlist_entry entry;

  if (nl80211_get_channel(iw, ifname, &ch_cur))
    ch_cur = 0;

  /* initialize the value pointer with channel for callback */
  dbm_max = ch_cur;

  err = nl80211_request(iw, ifname, NL80211_CMD_GET_WIPHY, 0,
                        nl80211_get_txpwrlist_cb, &dbm_max);

  if (!err) {
    for (dbm_cur = 0, dbm_cnt = 0; dbm_cur < dbm_max; dbm_cur++, dbm_cnt++) {
      entry.dbm = dbm_cur;
      entry.mw = iwinfo_dbm2mw(dbm_cur);

      memcpy(&buf[dbm_cnt * sizeof(entry)], &entry, sizeof(entry));
    }

    entry.dbm = dbm_max;
    entry.mw = iwinfo_dbm2mw(dbm_max);

    memcpy(&buf[dbm_cnt * sizeof(entry)], &entry, sizeof(entry));
    dbm_cnt++;

    *len = dbm_cnt * sizeof(entry);
    return 0;
  }

  return -1;
}

static void nl80211_get_scancrypto(char *spec, struct iwinfo_crypto_entry *c) {
  int wpa_version = 0;
  char *p, *q, *proto, *suites;

  c->enabled = 0;

  for (p = strtok_r(spec, "[]", &q); p; p = strtok_r(NULL, "[]", &q)) {
    if (!strcmp(p, "WEP")) {
      c->enabled = 1;
      c->auth_suites = IWINFO_KMGMT_NONE;
      c->auth_algs = IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED;
      c->pair_ciphers = IWINFO_CIPHER_WEP40 | IWINFO_CIPHER_WEP104;
      break;
    }

    proto = strtok(p, "-");
    suites = strtok(NULL, "]");

    if (!proto || !suites)
      continue;

    if (!strcmp(proto, "WPA2") || !strcmp(proto, "RSN"))
      wpa_version = 2;
    else if (!strcmp(proto, "WPA"))
      wpa_version = 1;
    else
      continue;

    c->enabled = 1;

    parse_wpa_suites(suites, wpa_version, &c->wpa_version, &c->auth_suites);
    parse_wpa_ciphers(suites, &c->pair_ciphers);
  }
}

struct nl80211_scanlist {
  struct iwinfo_scanlist_entry *e;
  int len;
};

static void nl80211_get_scanlist_ie(struct nlattr **bss,
                                    struct iwinfo_scanlist_entry *e) {
  int ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  unsigned char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  static unsigned char ms_oui[3] = {0x00, 0x50, 0xf2};
  int len;

  while (ielen >= 2 && ielen >= ie[1]) {
    switch (ie[0]) {
    case 0:   /* SSID */
    case 114: /* Mesh ID */
      if (e->ssid[0] == 0) {
        len = min(ie[1], IWINFO_ESSID_MAX_SIZE);
        memcpy(e->ssid, ie + 2, len);
        e->ssid[len] = 0;
      }
      break;

    case 48: /* RSN */
      iwinfo_parse_rsn(&e->crypto, ie + 2, ie[1], IWINFO_CIPHER_CCMP,
                       IWINFO_KMGMT_8021x);
      break;

    case 221: /* Vendor */
      if (ie[1] >= 4 && !memcmp(ie + 2, ms_oui, 3) && ie[5] == 1)
        iwinfo_parse_rsn(&e->crypto, ie + 6, ie[1] - 4, IWINFO_CIPHER_TKIP,
                         IWINFO_KMGMT_PSK);
      break;
    case 61: /* HT operation */
      if (ie[1] >= 3) {
        e->ht_chan_info.primary_chan = ie[2];
        e->ht_chan_info.secondary_chan_off = ie[3] & 0x3;
        e->ht_chan_info.chan_width = (ie[4] & 0x4) >> 2;
      }
      break;
    case 192: /* VHT operation */
      if (ie[1] >= 3) {
        e->vht_chan_info.chan_width = ie[2];
        e->vht_chan_info.center_chan_1 = ie[3];
        e->vht_chan_info.center_chan_2 = ie[4];
      }
      break;
    }

    ielen -= ie[1] + 2;
    ie += ie[1] + 2;
  }
}

static int nl80211_get_scanlist_cb(struct nl_msg *msg, void *arg) {
  // NLA_DBG("%s\n", __func__);
  int8_t rssi;
  uint16_t caps;

  struct nl80211_scanlist *sl = arg;
  struct nlattr **tb = nl80211_parse(msg);
  struct nlattr *bss[NL80211_BSS_MAX + 1];

  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
      [NL80211_BSS_TSF] = {.type = NLA_U64},
      [NL80211_BSS_FREQUENCY] = {.type = NLA_U32},
      [NL80211_BSS_BSSID] = {0},
      [NL80211_BSS_BEACON_INTERVAL] = {.type = NLA_U16},
      [NL80211_BSS_CAPABILITY] = {.type = NLA_U16},
      [NL80211_BSS_INFORMATION_ELEMENTS] = {0},
      [NL80211_BSS_SIGNAL_MBM] = {.type = NLA_U32},
      [NL80211_BSS_SIGNAL_UNSPEC] = {.type = NLA_U8},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
      [NL80211_BSS_SEEN_MS_AGO] = {.type = NLA_U32},
      [NL80211_BSS_BEACON_IES] = {0},
  };

  if (!tb[NL80211_ATTR_BSS] ||
      nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy) ||
      !bss[NL80211_BSS_BSSID]) {
    return NL_SKIP;
  }

  if (bss[NL80211_BSS_CAPABILITY])
    caps = nla_get_u16_safe(bss[NL80211_BSS_CAPABILITY]);
  else
    caps = 0;

  memset(sl->e, 0, sizeof(*sl->e));
  memcpy(sl->e->mac, nla_data(bss[NL80211_BSS_BSSID]), 6);

  if (caps & (1 << 1))
    sl->e->mode = IWINFO_OPMODE_ADHOC;
  else if (caps & (1 << 0))
    sl->e->mode = IWINFO_OPMODE_MASTER;
  else
    sl->e->mode = IWINFO_OPMODE_MESHPOINT;

  if (caps & (1 << 4))
    sl->e->crypto.enabled = 1;

  if (bss[NL80211_BSS_FREQUENCY]) {
    sl->e->mhz = nla_get_u32_safe(bss[NL80211_BSS_FREQUENCY]);
    sl->e->band = nl80211_freq2band(sl->e->mhz);
    sl->e->channel = nl80211_freq2channel(sl->e->mhz);
  }

  if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
    nl80211_get_scanlist_ie(bss, sl->e);

  if (bss[NL80211_BSS_SIGNAL_MBM]) {
    sl->e->signal =
        (uint8_t)((int32_t)nla_get_u32_safe(bss[NL80211_BSS_SIGNAL_MBM]) / 100);

    rssi = sl->e->signal - 0x100;

    if (rssi < -110)
      rssi = -110;
    else if (rssi > -40)
      rssi = -40;

    sl->e->quality = (rssi + 110);
    sl->e->quality_max = 70;
  }

  if (sl->e->crypto.enabled && !sl->e->crypto.wpa_version) {
    sl->e->crypto.auth_algs = IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED;
    sl->e->crypto.pair_ciphers = IWINFO_CIPHER_WEP40 | IWINFO_CIPHER_WEP104;
  }

  sl->e++;
  sl->len++;

  return NL_SKIP;
}

static int nl80211_get_scanlist_nl(iwinfo_t *iw, const char *ifname, char *buf,
                                   int *len) {
  // NLA_DBG("%s %s\n", __func__, ifname);
  struct nl80211_scanlist sl = {.e = (struct iwinfo_scanlist_entry *)buf};

  if (nl80211_request(iw, ifname, NL80211_CMD_TRIGGER_SCAN, 0, NULL, NULL))
    goto out;

  if (nl80211_wait(iw, "nl80211", "scan", NL80211_CMD_NEW_SCAN_RESULTS,
                   NL80211_CMD_SCAN_ABORTED))
    goto out;

  if (nl80211_request(iw, ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                      nl80211_get_scanlist_cb, &sl))
    goto out;

  *len = sl.len * sizeof(struct iwinfo_scanlist_entry);
  return 0;

out:
  *len = 0;
  return -1;
}

static int wpasupp_ssid_decode(const char *in, char *out, int outlen) {
#define hex(x)                                                                 \
  (((x) >= 'a') ? ((x) - 'a' + 10)                                             \
                : (((x) >= 'A') ? ((x) - 'A' + 10) : ((x) - '0')))

  int len = 0;

  while (*in) {
    if (len + 1 >= outlen)
      break;

    switch (*in) {
    case '\\':
      in++;
      switch (*in) {
      case 'n':
        out[len++] = '\n';
        in++;
        break;

      case 'r':
        out[len++] = '\r';
        in++;
        break;

      case 't':
        out[len++] = '\t';
        in++;
        break;

      case 'e':
        out[len++] = '\033';
        in++;
        break;

      case 'x':
        if (isxdigit(*(in + 1)) && isxdigit(*(in + 2)))
          out[len++] = hex(*(in + 1)) * 16 + hex(*(in + 2));
        in += 3;
        break;

      default:
        out[len++] = *in++;
        break;
      }
      break;

    default:
      out[len++] = *in++;
      break;
    }
  }

  if (outlen > len)
    out[len] = '\0';

  return len;
}

static int nl80211_get_scanlist_wpactl(iwinfo_t *iw, const char *ifname,
                                       char *buf, int *len) {
  int sock, qmax, rssi, tries, count = -1, ready = 0;
  char *pos, *line, *bssid, *freq, *signal, *flags, *ssid, reply[4096];
  struct sockaddr_un local = {0};
  struct iwinfo_scanlist_entry *e = (struct iwinfo_scanlist_entry *)buf;

  sock = nl80211_wpactl_connect(ifname, &local);

  if (sock < 0)
    return sock;

  send(sock, "ATTACH", 6, 0);
  send(sock, "SCAN passive=1", 4, 0);

  /*
   * wait for scan results:
   *   nl80211_wpactl_recv() will use a timeout of 256ms and we need to scan
   *   72 channels at most. We'll also receive two "OK" messages acknowledging
   *   the "ATTACH" and "SCAN" commands and the driver might need a bit extra
   *   time to process the results, so try 72 + 2 + 1 times.
   */
  for (tries = 0; tries < 75; tries++) {
    if (nl80211_wpactl_recv(sock, reply, sizeof(reply)) <= 0)
      continue;

    /* got an event notification */
    if (reply[0] == '<') {
      /* scan results are ready */
      if (strstr(reply, "CTRL-EVENT-SCAN-RESULTS")) {
        /* send "SCAN_RESULTS" command */
        ready = (send(sock, "SCAN_RESULTS", 12, 0) == 12);
        break;
      }

      /* is another unrelated event, retry */
      tries--;
    }

    /* scanning already in progress, keep awaiting results */
    else if (!strcmp(reply, "FAIL-BUSY\n")) {
      tries--;
    }

    /* another failure, abort */
    else if (!strncmp(reply, "FAIL-", 5)) {
      break;
    }
  }

  /* receive and parse scan results if the wait above didn't time out */
  while (ready && nl80211_wpactl_recv(sock, reply, sizeof(reply)) > 0) {
    /* received an event notification, receive again */
    if (reply[0] == '<')
      continue;

    nl80211_get_quality_max(iw, ifname, &qmax);

    for (line = strtok_r(reply, "\n", &pos); line != NULL;
         line = strtok_r(NULL, "\n", &pos)) {
      /* skip header line */
      if (count < 0) {
        count++;
        continue;
      }

      bssid = strtok(line, "\t");
      freq = strtok(NULL, "\t");
      signal = strtok(NULL, "\t");
      flags = strtok(NULL, "\t");
      ssid = strtok(NULL, "\n");

      if (!bssid || !freq || !signal || !flags)
        continue;

      /* BSSID */
      e->mac[0] = strtol(&bssid[0], NULL, 16);
      e->mac[1] = strtol(&bssid[3], NULL, 16);
      e->mac[2] = strtol(&bssid[6], NULL, 16);
      e->mac[3] = strtol(&bssid[9], NULL, 16);
      e->mac[4] = strtol(&bssid[12], NULL, 16);
      e->mac[5] = strtol(&bssid[15], NULL, 16);

      /* SSID */
      if (ssid)
        wpasupp_ssid_decode(ssid, e->ssid, sizeof(e->ssid));
      else
        e->ssid[0] = 0;

      /* Mode */
      if (strstr(flags, "[MESH]"))
        e->mode = IWINFO_OPMODE_MESHPOINT;
      else if (strstr(flags, "[IBSS]"))
        e->mode = IWINFO_OPMODE_ADHOC;
      else
        e->mode = IWINFO_OPMODE_MASTER;

      /* Channel */
      e->mhz = atoi(freq);
      e->band = nl80211_freq2band(e->mhz);
      e->channel = nl80211_freq2channel(e->mhz);

      /* Signal */
      rssi = atoi(signal);
      e->signal = rssi;

      /* Quality */
      if (rssi < 0) {
        /* The cfg80211 wext compat layer assumes a signal range
         * of -110 dBm to -40 dBm, the quality value is derived
         * by adding 110 to the signal level */
        if (rssi < -110)
          rssi = -110;
        else if (rssi > -40)
          rssi = -40;

        e->quality = (rssi + 110);
      } else {
        e->quality = rssi;
      }

      /* Max. Quality */
      e->quality_max = qmax;

      /* Crypto */
      nl80211_get_scancrypto(flags, &e->crypto);

      count++;
      e++;
    }

    *len = count * sizeof(struct iwinfo_scanlist_entry);
    break;
  }

  close(sock);
  unlink(local.sun_path);

  return (count >= 0) ? 0 : -1;
}

static int nl80211_scan_trigger(iwinfo_t *iw, const char *ifname, int duration,
                                int freq, int duration_mandatory) {
  // NLA_DBG("%s %s\n", __func__, ifname);
  struct nl80211_msg_conveyor *cv;
  struct nlattr *freqs_nest = NULL;

  /* Create TRIGGER_SCAN message with parameters */
  cv = nl80211_msg(iw, ifname, NL80211_CMD_TRIGGER_SCAN, 0);
  if (!cv)
    goto out;

  /* Add frequency attribute if specified */
  if (freq > 0) {
    freqs_nest = nla_nest_start(cv->msg, NL80211_ATTR_SCAN_FREQUENCIES);
    if (!freqs_nest)
      goto nla_put_failure;
    /* Add frequency as u32 value with index 0 in nested attribute */
    /* In libnl-tiny, nested attributes use sequential indices starting from 0
     */
    NLA_PUT_U32(cv->msg, 0, freq);
    nla_nest_end(cv->msg, freqs_nest);
  }

  /* Add duration attribute if specified (in TUs, u16) */
  if (duration > 0) {
    NLA_PUT_U16(cv->msg, NL80211_ATTR_MEASUREMENT_DURATION, (uint16_t)duration);
  }

  /* Add duration_mandatory flag if specified */
  if (duration_mandatory) {
    NLA_PUT_FLAG(cv->msg, NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY);
  }

  /* Send trigger scan request */
  if (nl80211_send(iw, NULL, NULL))
    goto out;

  /* Wait for scan to complete */
  if (nl80211_wait(iw, "nl80211", "scan", NL80211_CMD_NEW_SCAN_RESULTS,
                   NL80211_CMD_SCAN_ABORTED))
    goto out;

  return 0;

nla_put_failure:
  nl80211_free(cv);
out:
  return -1;
}

static int nl80211_scan_get(iwinfo_t *iw, const char *ifname, char *buf,
                            int *len) {
  // NLA_DBG("%s %s\n", __func__, ifname);
  struct nl80211_scanlist sl = {.e = (struct iwinfo_scanlist_entry *)buf};

  if (nl80211_request(iw, ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                      nl80211_get_scanlist_cb, &sl))
    goto out;

  *len = sl.len * sizeof(struct iwinfo_scanlist_entry);
  return 0;

out:
  *len = 0;
  return -1;
}

static int nl80211_get_scanlist2(iwinfo_t *iw, const char *ifname, int duration,
                                 int freq, int duration_mandatory, char *buf,
                                 int *len) {
  // NLA_DBG("%s %s\n", __func__, ifname);

  /* Trigger scan with parameters */
  if (nl80211_scan_trigger(iw, ifname, duration, freq, duration_mandatory))
    goto out;

  /* Get scan results */
  if (nl80211_scan_get(iw, ifname, buf, len))
    goto out;

  return 0;

out:
  *len = 0;
  return -1;
}

static int nl80211_get_scanlist(iwinfo_t *iw, const char *ifname, char *buf,
                                int *len) {
  // NLA_DBG("%s %s\n", __func__, ifname);

  char *res;
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';

  int rv, mode;

  *len = 0;

  /* Got a radioX pseudo interface, find some interface on it or create one */
  if (!strncmp(ifname, "radio", 5)) {
    /* Reuse existing interface */
    if ((res = nl80211_phy2ifname(iw, resbuf, ifname)) != NULL) {
      return nl80211_get_scanlist(iw, res, buf, len);
    }

    /* Need to spawn a temporary iface for scanning */
    else if ((res = nl80211_ifadd(iw, resbuf, ifname)) != NULL) {
      rv = nl80211_get_scanlist(iw, res, buf, len);
      nl80211_ifdel(iw, res);
      return rv;
    }
  }

  /* WPA supplicant */
  if (!nl80211_get_scanlist_wpactl(iw, ifname, buf, len)) {
    return 0;
  }

  /* station / ad-hoc / monitor scan */
  else if (!nl80211_get_mode(iw, ifname, &mode) &&
           (mode == IWINFO_OPMODE_ADHOC || mode == IWINFO_OPMODE_MASTER ||
            mode == IWINFO_OPMODE_CLIENT || mode == IWINFO_OPMODE_MONITOR) &&
           iwinfo_ifup(ifname)) {
    return nl80211_get_scanlist_nl(iw, ifname, buf, len);
  }

  /* AP scan */
  else {
    /* Got a temp interface, don't create yet another one */
    if (!strncmp(ifname, "tmp.", 4)) {
      if (!iwinfo_ifup(ifname))
        return -1;

      rv = nl80211_get_scanlist_nl(iw, ifname, buf, len);
      iwinfo_ifdown(ifname);
      return rv;
    }

    /* Spawn a new scan interface */
    else {
      if (!(res = nl80211_ifadd(iw, resbuf, ifname)))
        return -1;

      iwinfo_ifmac(res);

      /* if we can take the new interface up, the driver supports an
       * additional interface and there's no need to tear down the ap */
      if (iwinfo_ifup(res)) {
        rv = nl80211_get_scanlist_nl(iw, res, buf, len);
        iwinfo_ifdown(res);
      }

      /* driver cannot create secondary interface, take down ap
       * during scan */
      else if (iwinfo_ifdown(ifname) && iwinfo_ifup(res)) {
        rv = nl80211_get_scanlist_nl(iw, res, buf, len);
        iwinfo_ifdown(res);
        iwinfo_ifup(ifname);
        nl80211_hostapd_hup(iw, ifname);
      } else
        rv = -1;

      nl80211_ifdel(iw, res);
      return rv;
    }
  }

  return -1;
}

static int nl80211_get_freqlist_cb(struct nl_msg *msg, void *arg) {
  int bands_remain, freqs_remain;

  struct nl80211_array_buf *arr = arg;
  struct iwinfo_freqlist_entry *e;

  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *bands[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *freqs[NL80211_FREQUENCY_ATTR_MAX + 1];
  struct nlattr *band, *freq;

  e = arr->buf;
  e += arr->count;

  if (attr[NL80211_ATTR_WIPHY_BANDS]) {
    nla_for_each_nested(band, attr[NL80211_ATTR_WIPHY_BANDS], bands_remain) {
      nla_parse(bands, NL80211_BAND_ATTR_MAX, nla_data(band), nla_len(band),
                NULL);

      if (bands[NL80211_BAND_ATTR_FREQS]) {
        nla_for_each_nested(freq, bands[NL80211_BAND_ATTR_FREQS],
                            freqs_remain) {
          nla_parse(freqs, NL80211_FREQUENCY_ATTR_MAX, nla_data(freq),
                    nla_len(freq), NULL);

          if (!freqs[NL80211_FREQUENCY_ATTR_FREQ] ||
              freqs[NL80211_FREQUENCY_ATTR_DISABLED])
            continue;

          e->band = nl80211_get_band(band->nla_type);
          e->mhz = nla_get_u32_safe(freqs[NL80211_FREQUENCY_ATTR_FREQ]);
          e->channel = nl80211_freq2channel(e->mhz);

          if (freqs[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS])
            e->flags |= IWINFO_FREQ_NO_HT40MINUS;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS])
            e->flags |= IWINFO_FREQ_NO_HT40PLUS;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_80MHZ])
            e->flags |= IWINFO_FREQ_NO_80MHZ;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_160MHZ])
            e->flags |= IWINFO_FREQ_NO_160MHZ;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_20MHZ])
            e->flags |= IWINFO_FREQ_NO_20MHZ;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_10MHZ])
            e->flags |= IWINFO_FREQ_NO_10MHZ;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_HE])
            e->flags |= IWINFO_FREQ_NO_HE;
          if (freqs[NL80211_FREQUENCY_ATTR_NO_IR] &&
              !freqs[NL80211_FREQUENCY_ATTR_RADAR])
            e->flags |= IWINFO_FREQ_NO_IR;
          if (freqs[NL80211_FREQUENCY_ATTR_INDOOR_ONLY])
            e->flags |= IWINFO_FREQ_INDOOR_ONLY;

          /* keep backwards compatibility */
          e->restricted = (e->flags & IWINFO_FREQ_NO_IR) ? 1 : 0;

          e++;
          arr->count++;
        }
      }
    }
  }

  return NL_SKIP;
}

static int nl80211_get_freqlist(iwinfo_t *iw, const char *ifname, char *buf,
                                int *len) {
  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  struct nl80211_array_buf arr = {.buf = buf, .count = 0};
  uint32_t features = nl80211_get_protocol_features(iw, ifname);
  int flags;

  flags = features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP ? NLM_F_DUMP : 0;
  cv = nl80211_msg(iw, ifname, NL80211_CMD_GET_WIPHY, flags);
  if (!cv)
    goto out;

  NLA_PUT_FLAG(cv->msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
  if (nl80211_send(iw, nl80211_get_freqlist_cb, &arr))
    goto out;

  *len = arr.count * sizeof(struct iwinfo_freqlist_entry);
  return 0;

nla_put_failure:
  nl80211_free(cv);
out:
  *len = 0;
  return -1;
}

static int nl80211_get_country_cb(struct nl_msg *msg, void *arg) {
  char *buf = arg;
  struct nlattr **attr = nl80211_parse(msg);

  if (attr[NL80211_ATTR_REG_ALPHA2])
    memcpy(buf, nla_data(attr[NL80211_ATTR_REG_ALPHA2]), 2);
  else
    buf[0] = 0;

  return NL_SKIP;
}

static int nl80211_get_country(iwinfo_t *iw, const char *ifname, char *buf) {
  if (nl80211_request(iw, ifname, NL80211_CMD_GET_REG, 0,
                      nl80211_get_country_cb, buf))
    return -1;

  return 0;
}

static int nl80211_get_countrylist(iwinfo_t *iw, const char *ifname, char *buf,
                                   int *len) {
  int count;
  struct iwinfo_country_entry *e = (struct iwinfo_country_entry *)buf;
  const struct iwinfo_iso3166_label *l;

  for (l = IWINFO_ISO3166_NAMES, count = 0; l->iso3166; l++, e++, count++) {
    e->iso3166 = l->iso3166;
    e->ccode[0] = (l->iso3166 / 256);
    e->ccode[1] = (l->iso3166 % 256);
    e->ccode[2] = 0;
  }

  *len = (count * sizeof(struct iwinfo_country_entry));
  return 0;
}

struct nl80211_modes {
  bool ok;
  uint32_t hw;
  uint32_t ht;

  uint8_t bands;

  uint16_t nl_ht;
  uint32_t nl_vht;
  uint16_t he_phy_cap[6];
};

static void nl80211_eval_modelist(struct nl80211_modes *m) {
  /* Treat any nonzero capability as 11n */
  if (m->nl_ht > 0) {
    m->hw |= IWINFO_80211_N;
    m->ht |= IWINFO_HTMODE_HT20;

    if (m->nl_ht & (1 << 1))
      m->ht |= IWINFO_HTMODE_HT40;
  }

  if (m->he_phy_cap[0] != 0) {
    m->hw |= IWINFO_80211_AX;
    m->ht |= IWINFO_HTMODE_HE20;

    if (m->he_phy_cap[0] & BIT(9))
      m->ht |= IWINFO_HTMODE_HE40;
    if (m->he_phy_cap[0] & BIT(10))
      m->ht |= IWINFO_HTMODE_HE40 | IWINFO_HTMODE_HE80;
    if (m->he_phy_cap[0] & BIT(11))
      m->ht |= IWINFO_HTMODE_HE160;
    if (m->he_phy_cap[0] & BIT(12))
      m->ht |= IWINFO_HTMODE_HE160 | IWINFO_HTMODE_HE80_80;
  }

  if (m->bands & IWINFO_BAND_24) {
    m->hw |= IWINFO_80211_B;
    m->hw |= IWINFO_80211_G;
  }

  if (m->bands & IWINFO_BAND_5) {
    /* Treat any nonzero capability as 11ac */
    if (m->nl_vht > 0) {
      m->hw |= IWINFO_80211_AC;
      m->ht |= IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80;

      switch ((m->nl_vht >> 2) & 3) {
      case 2:
        m->ht |= IWINFO_HTMODE_VHT80_80;
        /* fall through */

      case 1:
        m->ht |= IWINFO_HTMODE_VHT160;
      }
    } else {
      m->hw |= IWINFO_80211_A;
    }
  }

  if (m->bands & IWINFO_BAND_60) {
    m->hw |= IWINFO_80211_AD;
  }
}

static int nl80211_get_modelist_cb(struct nl_msg *msg, void *arg) {
  // NLA_DBG("%s\n", __func__);
  struct nl80211_modes *m = arg;
  int bands_remain;
  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *bands[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *band;

  if (attr[NL80211_ATTR_WIPHY_BANDS]) {
    nla_for_each_nested(band, attr[NL80211_ATTR_WIPHY_BANDS], bands_remain) {
      m->bands |= nl80211_get_band(band->nla_type);

      nla_parse(bands, NL80211_BAND_ATTR_MAX, nla_data(band), nla_len(band),
                NULL);

      if (bands[NL80211_BAND_ATTR_HT_CAPA])
        m->nl_ht = nla_get_u16_safe(bands[NL80211_BAND_ATTR_HT_CAPA]);

      if (bands[NL80211_BAND_ATTR_VHT_CAPA])
        m->nl_vht = nla_get_u32_safe(bands[NL80211_BAND_ATTR_VHT_CAPA]);

      if (bands[NL80211_BAND_ATTR_IFTYPE_DATA]) {
        struct nlattr *tb[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
        struct nlattr *nl_iftype;
        int rem_band;
        int len;

        nla_for_each_nested(nl_iftype, bands[NL80211_BAND_ATTR_IFTYPE_DATA],
                            rem_band) {
          nla_parse(tb, NL80211_BAND_IFTYPE_ATTR_MAX, nla_data(nl_iftype),
                    nla_len(nl_iftype), NULL);
          if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]) {
            len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]);

            if (len > sizeof(m->he_phy_cap) - 1)
              len = sizeof(m->he_phy_cap) - 1;
            memcpy(&((__u8 *)m->he_phy_cap)[1],
                   nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]), len);
          }
        }
      }
    }

    m->ok = 1;
  }

  return NL_SKIP;
}

static int nl80211_get_hwmodelist(iwinfo_t *iw, const char *ifname, int *buf) {
  // NLA_DBG("%s\n", __func__);
  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  struct nl80211_modes m = {0};
  uint32_t features = nl80211_get_protocol_features(iw, ifname);
  int flags;

  flags = features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP ? NLM_F_DUMP : 0;
  cv = nl80211_msg(iw, ifname, NL80211_CMD_GET_WIPHY, flags);
  if (!cv) {
    // NLA_DBG("%s nl80211_msg\n", __func__);
    goto out;
  }

  NLA_PUT_FLAG(cv->msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
  if (nl80211_send(iw, nl80211_get_modelist_cb, &m)) {
    // NLA_DBG("%s nl80211_send\n", __func__);
    goto nla_put_failure;
  }

  nl80211_eval_modelist(&m);

  *buf = m.hw;

  return 0;

nla_put_failure:
  // NLA_DBG("%s nla_put_failure\n", __func__);
  nl80211_free(cv);
out:
  return -1;
}

struct chan_info {
  int width;
  int mode;
};

static int nl80211_get_htmode_cb(struct nl_msg *msg, void *arg) {
  struct nlattr **tb = nl80211_parse(msg);
  struct nlattr *cur;
  struct chan_info *chn = arg;

  if ((cur = tb[NL80211_ATTR_CHANNEL_WIDTH]))
    chn->width = nla_get_u32_safe(cur);

  if ((cur = tb[NL80211_ATTR_BSS_HT_OPMODE]))
    chn->mode = nla_get_u32_safe(cur);

  return NL_SKIP;
}

static int nl80211_get_htmode(iwinfo_t *iw, const char *ifname, int *buf) {
  struct chan_info chn = {0};
  char *res, b[2] = {0};
  char resbuf[IFNAMSIZ];
  resbuf[0] = '\0';
  int err;
  bool he = false;

  res = nl80211_phy2ifname(iw, resbuf, ifname);
  *buf = 0;

  err = nl80211_request(iw, res ? res : ifname, NL80211_CMD_GET_INTERFACE, 0,
                        nl80211_get_htmode_cb, &chn);
  if (err)
    return -1;

  if (nl80211_hostapd_query(iw, res ? res : ifname, "ieee80211ax", b,
                            sizeof(b)))
    he = b[0] == '1';
  else if (nl80211_wpactl_query(iw, res ? res : ifname, "wifi_generation", b,
                                sizeof(b)))
    he = b[0] == '6';

  switch (chn.width) {
  case NL80211_CHAN_WIDTH_20:
    if (he)
      *buf = IWINFO_HTMODE_HE20;
    else if (chn.mode == -1)
      *buf = IWINFO_HTMODE_VHT20;
    else
      *buf = IWINFO_HTMODE_HT20;
    break;
  case NL80211_CHAN_WIDTH_40:
    if (he)
      *buf = IWINFO_HTMODE_HE40;
    else if (chn.mode == -1)
      *buf = IWINFO_HTMODE_VHT40;
    else
      *buf = IWINFO_HTMODE_HT40;
    break;
  case NL80211_CHAN_WIDTH_80:
    if (he)
      *buf = IWINFO_HTMODE_HE80;
    else
      *buf = IWINFO_HTMODE_VHT80;
    break;
  case NL80211_CHAN_WIDTH_80P80:
    if (he)
      *buf = IWINFO_HTMODE_HE80_80;
    else
      *buf = IWINFO_HTMODE_VHT80_80;
    break;
  case NL80211_CHAN_WIDTH_160:
    if (he)
      *buf = IWINFO_HTMODE_HE160;
    else
      *buf = IWINFO_HTMODE_VHT160;
    break;
  case NL80211_CHAN_WIDTH_5:
  case NL80211_CHAN_WIDTH_10:
  case NL80211_CHAN_WIDTH_20_NOHT:
    *buf = IWINFO_HTMODE_NOHT;
    break;
  default:
    return -1;
  }

  return 0;
}

static int nl80211_get_htmodelist(iwinfo_t *iw, const char *ifname, int *buf) {
  if (iw == NULL)
    return -1;
  struct nl80211_msg_conveyor *cv = &iw->state.cv;
  struct nl80211_modes m = {};
  uint32_t features = nl80211_get_protocol_features(iw, ifname);
  int flags;

  flags = features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP ? NLM_F_DUMP : 0;
  cv = nl80211_msg(iw, ifname, NL80211_CMD_GET_WIPHY, flags);
  if (!cv)
    goto out;

  NLA_PUT_FLAG(cv->msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
  if (nl80211_send(iw, nl80211_get_modelist_cb, &m))
    goto nla_put_failure;

  nl80211_eval_modelist(&m);

  *buf = m.ht;

  return 0;

nla_put_failure:
  nl80211_free(cv);
out:
  return -1;
}

static int nl80211_get_ifcomb_cb(struct nl_msg *msg, void *arg) {
  struct nlattr **attr = nl80211_parse(msg);
  struct nlattr *comb;
  int *ret = arg;
  int comb_rem, limit_rem, mode_rem;

  *ret = 0;
  if (!attr[NL80211_ATTR_INTERFACE_COMBINATIONS])
    return NL_SKIP;

  nla_for_each_nested(comb, attr[NL80211_ATTR_INTERFACE_COMBINATIONS],
                      comb_rem) {
    static struct nla_policy iface_combination_policy[NUM_NL80211_IFACE_COMB] =
        {
            [NL80211_IFACE_COMB_LIMITS] = {.type = NLA_NESTED},
            [NL80211_IFACE_COMB_MAXNUM] = {.type = NLA_U32},
        };
    struct nlattr *tb_comb[NUM_NL80211_IFACE_COMB + 1];
    static struct nla_policy iface_limit_policy[NUM_NL80211_IFACE_LIMIT] = {
        [NL80211_IFACE_LIMIT_TYPES] = {.type = NLA_NESTED},
        [NL80211_IFACE_LIMIT_MAX] = {.type = NLA_U32},
    };
    struct nlattr *tb_limit[NUM_NL80211_IFACE_LIMIT + 1];
    struct nlattr *limit;

    nla_parse_nested(tb_comb, NUM_NL80211_IFACE_COMB, comb,
                     iface_combination_policy);

    if (!tb_comb[NL80211_IFACE_COMB_LIMITS])
      continue;

    nla_for_each_nested(limit, tb_comb[NL80211_IFACE_COMB_LIMITS], limit_rem) {
      struct nlattr *mode;

      nla_parse_nested(tb_limit, NUM_NL80211_IFACE_LIMIT, limit,
                       iface_limit_policy);

      if (!tb_limit[NL80211_IFACE_LIMIT_TYPES] ||
          !tb_limit[NL80211_IFACE_LIMIT_MAX])
        continue;

      if (nla_get_u32_safe(tb_limit[NL80211_IFACE_LIMIT_MAX]) < 2)
        continue;

      nla_for_each_nested(mode, tb_limit[NL80211_IFACE_LIMIT_TYPES], mode_rem) {
        if (nla_type(mode) == NL80211_IFTYPE_AP)
          *ret = 1;
      }
    }
  }

  return NL_SKIP;
}

static int nl80211_get_mbssid_support(iwinfo_t *iw, const char *ifname,
                                      int *buf) {
  if (nl80211_request(iw, ifname, NL80211_CMD_GET_WIPHY, 0,
                      nl80211_get_ifcomb_cb, buf))
    return -1;

  return 0;
}

static int nl80211_hardware_id_from_fdt(iwinfo_t *iw,
                                        struct iwinfo_hardware_id *id,
                                        const char *ifname) {
  char *phy, path[PATH_MAX];
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';

  /* Try to determine the phy name from the given interface */
  phy = nl80211_ifname2phy(iw, phybuf, ifname);

  snprintf(path, sizeof(path), "/sys/class/%s/%s/device/of_node/compatible",
           phy ? "ieee80211" : "net", phy ? phy : ifname);

  if (nl80211_readstr(path, id->compatible, sizeof(id->compatible)) <= 0)
    return -1;

  return 0;
}

static int nl80211_get_hardware_id(iwinfo_t *iw, const char *ifname,
                                   char *buf) {
  struct iwinfo_hardware_id *id = (struct iwinfo_hardware_id *)buf;
  char *phy, num[8], path[PATH_MAX];
  char phybuf[IFNAMSIZ];
  phybuf[0] = '\0';
  int i;

  struct {
    const char *path;
    uint16_t *dest;
  } lookup[] = {{"vendor", &id->vendor_id},
                {"device", &id->device_id},
                {"subsystem_vendor", &id->subsystem_vendor_id},
                {"subsystem_device", &id->subsystem_device_id},
                {"../idVendor", &id->subsystem_vendor_id},
                {"../idProduct", &id->subsystem_device_id}};

  memset(id, 0, sizeof(*id));

  /* Try to determine the phy name from the given interface */
  phy = nl80211_ifname2phy(iw, phybuf, ifname);

  for (i = 0; i < ARRAY_SIZE(lookup); i++) {
    snprintf(path, sizeof(path), "/sys/class/%s/%s/device/%s",
             phy ? "ieee80211" : "net", phy ? phy : ifname, lookup[i].path);

    if (nl80211_readstr(path, num, sizeof(num)) > 0)
      *lookup[i].dest = strtoul(num, NULL, 16);
  }

  /* Failed to obtain hardware PCI/USB IDs... */
  if (id->vendor_id == 0 && id->device_id == 0 &&
      id->subsystem_vendor_id == 0 && id->subsystem_device_id == 0)
    /* ... first fallback to FDT ... */
    if (nl80211_hardware_id_from_fdt(iw, id, ifname) == -1)
      /* ... then board config */
      return iwinfo_hardware_id_from_mtd(id);

  return 0;
}

static const struct iwinfo_hardware_entry *
nl80211_get_hardware_entry(iwinfo_t *iw, const char *ifname) {
  struct iwinfo_hardware_id id;

  if (nl80211_get_hardware_id(iw, ifname, (char *)&id))
    return NULL;

  return iwinfo_hardware(&id);
}

static int nl80211_get_hardware_name(iwinfo_t *iw, const char *ifname,
                                     char *buf) {
  const struct iwinfo_hardware_entry *hw;

  if (!(hw = nl80211_get_hardware_entry(iw, ifname)))
    sprintf(buf, "Generic MAC80211");
  else
    sprintf(buf, "%s %s", hw->vendor_name, hw->device_name);

  return 0;
}

static int nl80211_get_txpower_offset(iwinfo_t *iw, const char *ifname,
                                      int *buf) {
  const struct iwinfo_hardware_entry *hw;

  if (!(hw = nl80211_get_hardware_entry(iw, ifname)))
    return -1;

  *buf = hw->txpower_offset;
  return 0;
}

static int nl80211_get_frequency_offset(iwinfo_t *iw, const char *ifname,
                                        int *buf) {
  const struct iwinfo_hardware_entry *hw;

  if (!(hw = nl80211_get_hardware_entry(iw, ifname)))
    return -1;

  *buf = hw->frequency_offset;
  return 0;
}

static int nl80211_lookup_phyname(iwinfo_t *iw, const char *section,
                                  char *buf) {
  const char *ifname = NULL;
  char namebuf[IFNAMSIZ];
  namebuf[0] = '\0';
  int idx = -1;

  if (!strncmp(section, "path=", 5))
    idx = nl80211_phy_idx_from_path(section + 5);
  else if (!strncmp(section, "macaddr=", 8))
    idx = nl80211_phy_idx_from_macaddr(section + 8);

  if (idx < 0)
    return -1;

  ifname = nl80211_phyidx2name(iw, namebuf, idx);
  if (!ifname)
    return -1;

  strcpy(buf, ifname);
  return 0;
}

static int nl80211_get_station_dump(iwinfo_t *iw, const char *ifname,
                                    const uint8_t *mac,
                                    struct iwinfo_assoclist_entry *buf) {
  struct nl80211_msg_conveyor *cv;
  struct nl80211_array_buf arr = {
      .buf = (char *)buf, .count = 0, .max_count = 1};

  cv = nl80211_msg(iw, ifname, NL80211_CMD_GET_STATION, 0);
  if (!cv)
    return -1;

  NLA_PUT(cv->msg, NL80211_ATTR_MAC, 6, mac);

  if (nl80211_send(iw, nl80211_get_assoclist_cb, &arr))
    goto nla_put_failure;

  return (arr.count > 0) ? 0 : -1;

nla_put_failure:
  nl80211_free(cv);
  return -1;
}

static int nl80211_get_survey_freq(iwinfo_t *iw, const char *ifname,
                                   struct iwinfo_survey_entry *entry) {
  int freq;
  if (nl80211_get_frequency(iw, ifname, &freq))
    return -1;

  int len = 16384;
  char *buf = malloc(len);
  if (!buf)
    return -ENOMEM;

  if (nl80211_get_survey(iw, ifname, buf, &len)) {
    free(buf);
    return -1;
  }

  struct iwinfo_survey_entry *entries = (struct iwinfo_survey_entry *)buf;
  int count = len / sizeof(struct iwinfo_survey_entry);
  int found = 0;

  for (int i = 0; i < count; i++) {
    if (entries[i].mhz == freq) {
      *entry = entries[i];
      found = 1;
      break;
    }
  }
  free(buf);
  return found ? 0 : -1;
}

static int nl80211_get_total_sta_durations(iwinfo_t *iw, const char *ifname,
                                           uint64_t *tx_us, uint64_t *rx_us) {
  char phy[IFNAMSIZ];
  char ifnames[16][IFNAMSIZ];
  int count = 0;
  int i, j;

  *tx_us = 0;
  *rx_us = 0;

  if (nl80211_ifname2phy(iw, phy, ifname)) {
    count = nl80211_phy2ifnames(iw, phy, ifnames, 16);
  }

  if (count == 0) {
    strncpy(ifnames[0], ifname, IFNAMSIZ - 1);
    ifnames[0][IFNAMSIZ - 1] = '\0';
    count = 1;
  }

  for (i = 0; i < count; i++) {
    char buf[IWINFO_BUFSIZE];
    int len = IWINFO_BUFSIZE;
    struct iwinfo_assoclist_entry *e;

    if (nl80211_get_assoclist(iw, ifnames[i], buf, &len))
      continue;

    for (j = 0; j < len; j += sizeof(struct iwinfo_assoclist_entry)) {
      e = (struct iwinfo_assoclist_entry *)&buf[j];
      *tx_us += e->tx_duration;
      *rx_us += e->rx_duration;
    }
  }

  return 0;
}

static int nl80211_get_airtime_survey(iwinfo_t *iw, const char *ifname,
                                      struct iwinfo_airtime_entry *buf) {
  struct iwinfo_survey_entry s0, s1;
  uint64_t sta_tx0, sta_rx0, sta_tx1, sta_rx1;
  int htmode = IWINFO_HTMODE_NOHT;

  if (nl80211_get_survey_freq(iw, ifname, &s0))
    return -1;
  if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx0, &sta_rx0))
    return -1;

  sleep(1);

  if (nl80211_get_survey_freq(iw, ifname, &s1))
    return -1;
  if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx1, &sta_rx1))
    return -1;

  uint64_t da = s1.active_time - s0.active_time;
  uint64_t db = s1.busy_time - s0.busy_time;
  uint64_t dt = s1.txtime - s0.txtime;
  uint64_t dr = s1.rxtime - s0.rxtime;
  uint64_t dbe = s1.busy_time_ext - s0.busy_time_ext;

  if (da == 0)
    return -1;

  uint64_t d_rx_all_sta_ms = (sta_rx1 - sta_rx0) / 1000;
  uint64_t d_tx_all_sta_ms = (sta_tx1 - sta_tx0) / 1000;

  buf->busy = (uint8_t)((db * 100) / da);
  buf->busy_ext = (uint8_t)((dbe * 100) / da);
  buf->tx_ap = (uint8_t)((d_tx_all_sta_ms * 100) / da);
  buf->rx_ap = (uint8_t)((d_rx_all_sta_ms * 100) / da);

  /* Formula for interference_ext depends on bandwidth */
  nl80211_get_htmode(iw, ifname, &htmode);
  bool is_wide =
      (htmode == IWINFO_HTMODE_HT40 || htmode == IWINFO_HTMODE_VHT40 ||
       htmode == IWINFO_HTMODE_VHT80 || htmode == IWINFO_HTMODE_VHT80_80 ||
       htmode == IWINFO_HTMODE_VHT160 || htmode == IWINFO_HTMODE_HE40 ||
       htmode == IWINFO_HTMODE_HE80 || htmode == IWINFO_HTMODE_HE80_80 ||
       htmode == IWINFO_HTMODE_HE160);

  // 1. Помехи (не Wi-Fi)
  buf->interference =
      (uint8_t)((db > dt + dr) ? ((db - dt - dr) * 100) / da : 0);
  buf->interference_ext =
      is_wide ? (uint8_t)((dbe > dt + d_rx_all_sta_ms)
                              ? ((dbe - dt - d_rx_all_sta_ms) * 100) / da
                              : 0)
              : 0;

  // 2. Чужие сети (Wi-Fi соседей)
  if (dr > d_rx_all_sta_ms)
    buf->other_ap = (uint8_t)(((dr - d_rx_all_sta_ms) * 100) / da);
  else
    buf->other_ap = 0;

  buf->tx_ext_ap = (uint8_t)(is_wide ? (dt * 100) / da : 0);
  buf->rx_ext_ap = (uint8_t)(is_wide ? (d_rx_all_sta_ms * 100) / da : 0);

  buf->noise = s1.noise;

  return 0;
}

static int nl80211_get_airtime_station(iwinfo_t *iw, const char *ifname,
                                       const uint8_t *mac, char *buf,
                                       int *len) {
  struct iwinfo_survey_entry s0, s1;
  struct iwinfo_assoclist_entry sta0, sta1;
  struct iwinfo_airtime_entry *e;
  int htmode = IWINFO_HTMODE_NOHT;

  /* Single station mode */
  if (mac) {
    if (*len < sizeof(struct iwinfo_airtime_entry))
      return -1;

    e = (struct iwinfo_airtime_entry *)buf;
    memset(e, 0, sizeof(*e));
    memcpy(e->mac, mac, 6);

    uint64_t sta_tx_all0, sta_rx_all0, sta_tx_all1, sta_rx_all1;

    if (nl80211_get_survey_freq(iw, ifname, &s0))
      return -1;
    if (nl80211_get_station_dump(iw, ifname, mac, &sta0))
      return -1;
    if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx_all0, &sta_rx_all0))
      return -1;

    sleep(1);

    if (nl80211_get_survey_freq(iw, ifname, &s1))
      return -1;
    if (nl80211_get_station_dump(iw, ifname, mac, &sta1))
      return -1;
    if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx_all1, &sta_rx_all1))
      return -1;

    uint64_t da = s1.active_time - s0.active_time;      /* ms */
    uint64_t db = s1.busy_time - s0.busy_time;          /* ms */
    uint64_t dt = s1.txtime - s0.txtime;                /* ms */
    uint64_t dr = s1.rxtime - s0.rxtime;                /* ms */
    uint64_t dbe = s1.busy_time_ext - s0.busy_time_ext; /* ms */

    if (da == 0)
      return -1;

    uint64_t d_sta_tx_ms = (sta1.tx_duration - sta0.tx_duration) / 1000;
    uint64_t d_sta_rx_ms = (sta1.rx_duration - sta0.rx_duration) / 1000;
    uint64_t d_rx_all_sta_ms = (sta_rx_all1 - sta_rx_all0) / 1000;
    uint64_t d_tx_all_sta_ms = (sta_tx_all1 - sta_tx_all0) / 1000;

    /* Formula for interference_ext depends on bandwidth */
    nl80211_get_htmode(iw, ifname, &htmode);
    bool is_wide =
        (htmode == IWINFO_HTMODE_HT40 || htmode == IWINFO_HTMODE_VHT40 ||
         htmode == IWINFO_HTMODE_VHT80 || htmode == IWINFO_HTMODE_VHT80_80 ||
         htmode == IWINFO_HTMODE_VHT160 || htmode == IWINFO_HTMODE_HE40 ||
         htmode == IWINFO_HTMODE_HE80 || htmode == IWINFO_HTMODE_HE80_80 ||
         htmode == IWINFO_HTMODE_HE160);

    e->busy = (uint8_t)((db * 100) / da);
    e->tx_ap = (uint8_t)((d_tx_all_sta_ms * 100) / da);
    e->rx_ap = (uint8_t)((d_rx_all_sta_ms * 100) / da);
    e->tx_sta = (uint8_t)((d_sta_tx_ms * 100) / da);
    e->rx_sta = (uint8_t)((d_sta_rx_ms * 100) / da);

    e->other_ap = dr > d_rx_all_sta_ms
                      ? (uint8_t)(((dr - d_rx_all_sta_ms) * 100) / da)
                      : 0;
    e->other_sta =
        dr > d_sta_rx_ms ? (uint8_t)(((dr - d_sta_rx_ms) * 100) / da) : 0;
    e->interference =
        (uint8_t)((db > dt + dr) ? ((db - dt - dr) * 100) / da : 0);

    e->busy_ext = (uint8_t)((dbe * 100) / da);
    e->tx_ext_ap = (uint8_t)(is_wide ? (d_tx_all_sta_ms * 100) / da : 0);
    e->rx_ext_ap = (uint8_t)(is_wide ? (d_rx_all_sta_ms * 100) / da : 0);
    e->interference_ext = 0;
    if (is_wide) {
      uint64_t our_traffic = d_tx_all_sta_ms + d_rx_all_sta_ms;
      // Если вторичный канал занят дольше, чем мы передавали/принимали
      if (dbe > our_traffic) {
        e->interference_ext = (uint8_t)(((dbe - our_traffic) * 100) / da);
      }
    }

    e->tx_ext_sta = (uint8_t)(is_wide ? (d_sta_tx_ms * 100) / da : 0);
    e->rx_ext_sta = (uint8_t)(is_wide ? (d_sta_rx_ms * 100) / da : 0);

    /* 1. Чистое время передачи пакетов (валидный Airtime без шума) */
    int usage_ext = (int)e->busy_ext - (int)e->interference_ext;
    if (usage_ext < 0)
      usage_ext = 0;

    /* 2. Other для AP: Всё время пакетов минус трафик нашей точки доступа */
    int temp_other_ext_ap = usage_ext - (int)e->tx_ext_ap - (int)e->rx_ext_ap;
    e->other_ext_ap = (temp_other_ext_ap > 0) ? (uint8_t)temp_other_ext_ap : 0;

    /* 3. Other для STA: Всё время пакетов минус трафик конкретной станции */
    int temp_other_ext_sta =
        usage_ext - (int)e->tx_ext_sta - (int)e->rx_ext_sta;
    e->other_ext_sta =
        (temp_other_ext_sta > 0) ? (uint8_t)temp_other_ext_sta : 0;

    e->noise = s1.noise;
    e->signal = sta1.signal;
    e->rx_rate = sta1.rx_rate;
    e->tx_rate = sta1.tx_rate;

    *len = sizeof(struct iwinfo_airtime_entry);
    return 0;
  }

  /* All stations mode */
  int len0 = IWINFO_BUFSIZE, len1 = IWINFO_BUFSIZE;
  char *buf0 = malloc(IWINFO_BUFSIZE);
  char *buf1 = malloc(IWINFO_BUFSIZE);
  if (!buf0 || !buf1) {
    free(buf0);
    free(buf1);
    return -ENOMEM;
  }

  uint64_t sta_tx_all0, sta_rx_all0, sta_tx_all1, sta_rx_all1;

  if (nl80211_get_survey_freq(iw, ifname, &s0))
    goto out_err;
  if (nl80211_get_assoclist(iw, ifname, buf0, &len0))
    goto out_err;
  if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx_all0, &sta_rx_all0))
    goto out_err;

  sleep(1);

  if (nl80211_get_survey_freq(iw, ifname, &s1))
    goto out_err;
  if (nl80211_get_assoclist(iw, ifname, buf1, &len1))
    goto out_err;
  if (nl80211_get_total_sta_durations(iw, ifname, &sta_tx_all1, &sta_rx_all1))
    goto out_err;

  uint64_t da = s1.active_time - s0.active_time;      /* ms */
  uint64_t db = s1.busy_time - s0.busy_time;          /* ms */
  uint64_t dt = s1.txtime - s0.txtime;                /* ms */
  uint64_t dr = s1.rxtime - s0.rxtime;                /* ms */
  uint64_t dbe = s1.busy_time_ext - s0.busy_time_ext; /* ms */

  if (da == 0)
    goto out_err;

  /* Calculate total RX duration for all stations */
  uint64_t d_tx_all_sta_ms = (sta_tx_all1 - sta_tx_all0) / 1000;
  uint64_t d_rx_all_sta_ms = (sta_rx_all1 - sta_rx_all0) / 1000;

  /* Formula for interference_ext depends on bandwidth */
  nl80211_get_htmode(iw, ifname, &htmode);
  bool is_wide =
      (htmode == IWINFO_HTMODE_HT40 || htmode == IWINFO_HTMODE_VHT40 ||
       htmode == IWINFO_HTMODE_VHT80 || htmode == IWINFO_HTMODE_VHT80_80 ||
       htmode == IWINFO_HTMODE_VHT160 || htmode == IWINFO_HTMODE_HE40 ||
       htmode == IWINFO_HTMODE_HE80 || htmode == IWINFO_HTMODE_HE80_80 ||
       htmode == IWINFO_HTMODE_HE160);

  int out_count = 0;
  int max_out = *len / sizeof(struct iwinfo_airtime_entry);

  e = (struct iwinfo_airtime_entry *)buf;
  int count0 = len0 / sizeof(struct iwinfo_assoclist_entry);
  int count1 = len1 / sizeof(struct iwinfo_assoclist_entry);
  struct iwinfo_assoclist_entry *entry0, *entry1;

  for (int i = 0; i < count1; i++) {
    if (out_count >= max_out)
      break;

    entry1 = &((struct iwinfo_assoclist_entry *)buf1)[i];
    entry0 = NULL;

    /* Find matching station in T0 */
    for (int j = 0; j < count0; j++) {
      if (!memcmp(((struct iwinfo_assoclist_entry *)buf0)[j].mac, entry1->mac,
                  6)) {
        entry0 = &((struct iwinfo_assoclist_entry *)buf0)[j];
        break;
      }
    }

    if (entry0) {
      memset(e, 0, sizeof(*e));
      memcpy(e->mac, entry1->mac, 6);

      uint64_t d_sta_tx_ms = (entry1->tx_duration - entry0->tx_duration) / 1000;
      uint64_t d_sta_rx_ms = (entry1->rx_duration - entry0->rx_duration) / 1000;

      e->busy = (uint8_t)((db * 100) / da);
      e->tx_ap = (uint8_t)((dt * 100) / da);
      e->rx_ap = (uint8_t)((dr * 100) / da);
      e->tx_sta = (uint8_t)((d_sta_tx_ms * 100) / da);
      e->rx_sta = (uint8_t)((d_sta_rx_ms * 100) / da);

      e->other_ap = dr > d_rx_all_sta_ms
                        ? (uint8_t)(((dr - d_rx_all_sta_ms) * 100) / da)
                        : 0;
      e->other_sta =
          dr > d_sta_rx_ms ? (uint8_t)(((dr - d_sta_rx_ms) * 100) / da) : 0;
      e->interference =
          (uint8_t)((db > dt + dr) ? ((db - dt - dr) * 100) / da : 0);

      e->busy_ext = (uint8_t)((dbe * 100) / da);
      e->tx_ext_ap = (uint8_t)(is_wide ? (d_tx_all_sta_ms * 100) / da : 0);
      e->rx_ext_ap = (uint8_t)(is_wide ? (d_rx_all_sta_ms * 100) / da : 0);
      e->interference_ext =
          is_wide
              ? (uint8_t)((dbe > dt + dr) ? ((dbe - dt - dr) * 100) / da : 0)
              : 0;

      e->tx_ext_sta = (uint8_t)(is_wide ? (d_sta_tx_ms * 100) / da : 0);
      e->rx_ext_sta = (uint8_t)(is_wide ? (d_sta_rx_ms * 100) / da : 0);

      e->noise = s1.noise;
      e->signal = entry1->signal;
      e->rx_rate = entry1->rx_rate;
      e->tx_rate = entry1->tx_rate;

      e++;
      out_count++;
    }
  }

  *len = out_count * sizeof(struct iwinfo_airtime_entry);
  free(buf0);
  free(buf1);
  return 0;

out_err:
  free(buf0);
  free(buf1);
  return -1;
}

static int nl80211_phy_path(iwinfo_t *iw, const char *phyname,
                            const char **path) {
  if (strchr(phyname, '/'))
    return -1;

  *path = nl80211_phy_path_str(phyname);
  if (!*path)
    return -1;

  return 0;
}

const struct iwinfo_ops nl80211_ops = {
    .name = "nl80211",
    .init = nl80211_init,
    .probe = nl80211_probe,
    .channel = nl80211_get_channel,
    .center_chan1 = nl80211_get_center_chan1,
    .center_chan2 = nl80211_get_center_chan2,
    .frequency = nl80211_get_frequency,
    .frequency_offset = nl80211_get_frequency_offset,
    .txpower = nl80211_get_txpower,
    .txpower_offset = nl80211_get_txpower_offset,
    .bitrate = nl80211_get_bitrate,
    .signal = nl80211_get_signal,
    .noise = nl80211_get_noise,
    .quality = nl80211_get_quality,
    .quality_max = nl80211_get_quality_max,
    .mbssid_support = nl80211_get_mbssid_support,
    .hwmodelist = nl80211_get_hwmodelist,
    .htmodelist = nl80211_get_htmodelist,
    .htmode = nl80211_get_htmode,
    .mode = nl80211_get_mode,
    .ssid = nl80211_get_ssid,
    .bssid = nl80211_get_bssid,
    .country = nl80211_get_country,
    .hardware_id = nl80211_get_hardware_id,
    .hardware_name = nl80211_get_hardware_name,
    .encryption = nl80211_get_encryption,
    .phyname = nl80211_get_phyname,
    .assoclist = nl80211_get_assoclist,
    .txpwrlist = nl80211_get_txpwrlist,
    .scanlist = nl80211_get_scanlist,
    .scan_trigger = nl80211_scan_trigger,
    .scan_get = nl80211_scan_get,
    .freqlist = nl80211_get_freqlist,
    .countrylist = nl80211_get_countrylist,
    .survey = nl80211_get_survey,
    .station_dump = nl80211_get_station_dump,
    .airtime_survey = nl80211_get_airtime_survey,
    .airtime_station = nl80211_get_airtime_station,
    .lookup_phy = nl80211_lookup_phyname,
    .phy_path = nl80211_phy_path,
    .phy_to_ifnames = nl80211_phy2ifnames,
    .close = nl80211_close};
