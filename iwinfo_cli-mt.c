/*
 * iwinfo - Wireless Information Library - Command line frontend
 *
 *   Copyright (C) 2011 Jo-Philipp Wich <xm@subsignal.org>
 *
 * The iwinfo library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * The iwinfo library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with the iwinfo library. If not, see http://www.gnu.org/licenses/.
 */

#include <glob.h>
#include <stdio.h>

#include "iwinfo-mt.h"

static char *format_bssid(unsigned char *mac) {
  static char buf[18];

  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return buf;
}

static char *format_ssid(char *ssid) {
  static char buf[IWINFO_ESSID_MAX_SIZE + 3];

  if (ssid && ssid[0])
    snprintf(buf, sizeof(buf), "\"%s\"", ssid);
  else
    snprintf(buf, sizeof(buf), "unknown");

  return buf;
}

static const char *format_band(int band) {
  const char *name;

  name = iwinfo_band_name(band);
  if (name)
    return name;

  return "unknown";
}

static char *format_channel(int ch) {
  static char buf[16];

  if (ch <= 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d", ch);

  return buf;
}

static char *format_frequency(int freq) {
  static char buf[11];

  if (freq <= 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%.3f GHz", ((float)freq / 1000.0));

  return buf;
}

static char *format_freqflags(uint32_t flags) {
  static char str[512] = "[";
  char *pos = str + 1;
  int i;

  if (!flags)
    return "";

  for (i = 0; i < IWINFO_FREQ_FLAG_COUNT; i++)
    if (flags & (1 << i))
      pos += sprintf(pos, "%s, ", IWINFO_FREQ_FLAG_NAMES[i]);

  *(pos - 2) = ']';
  *(pos - 1) = 0;

  return str;
}

static char *format_txpower(int pwr) {
  static char buf[16];

  if (pwr < 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d dBm", pwr);

  return buf;
}

static char *format_quality(int qual) {
  static char buf[16];

  if (qual < 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d", qual);

  return buf;
}

static char *format_quality_max(int qmax) {
  static char buf[16];

  if (qmax < 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d", qmax);

  return buf;
}

static char *format_signal(int sig) {
  static char buf[10];

  if (!sig)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d dBm", sig);

  return buf;
}

static char *format_noise(int noise) {
  static char buf[10];

  if (!noise)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d dBm", noise);

  return buf;
}

static char *format_rate(int rate) {
  static char buf[18];

  if (rate <= 0)
    snprintf(buf, sizeof(buf), "unknown");
  else
    snprintf(buf, sizeof(buf), "%d.%d MBit/s",
             rate / 1000, (rate % 1000) / 100);

  return buf;
}

static char *format_enc_ciphers(int ciphers) {
  static char str[128] = {0};
  char *pos = str;
  int i;

  for (i = 0; i < IWINFO_CIPHER_COUNT; i++)
    if (ciphers & (1 << i))
      pos += sprintf(pos, "%s, ", IWINFO_CIPHER_NAMES[i]);

  *(pos - 2) = 0;

  return str;
}

static char *format_enc_suites(int suites) {
  static char str[64] = {0};
  char *pos = str;
  int i;

  for (i = 0; i < IWINFO_KMGMT_COUNT; i++)
    if (suites & (1 << i))
      pos += sprintf(pos, "%s/", IWINFO_KMGMT_NAMES[i]);

  *(pos - 1) = 0;

  return str;
}

static char *format_encryption(struct iwinfo_crypto_entry *c) {
  static char buf[512];
  char *pos = buf;
  int i, n;

  if (!c) {
    snprintf(buf, sizeof(buf), "unknown");
  } else if (c->enabled) {
    /* WEP */
    if (c->auth_algs && !c->wpa_version) {
      if ((c->auth_algs & IWINFO_AUTH_OPEN) &&
          (c->auth_algs & IWINFO_AUTH_SHARED)) {
        snprintf(buf, sizeof(buf), "WEP Open/Shared (%s)",
                 format_enc_ciphers(c->pair_ciphers));
      } else if (c->auth_algs & IWINFO_AUTH_OPEN) {
        snprintf(buf, sizeof(buf), "WEP Open System (%s)",
                 format_enc_ciphers(c->pair_ciphers));
      } else if (c->auth_algs & IWINFO_AUTH_SHARED) {
        snprintf(buf, sizeof(buf), "WEP Shared Auth (%s)",
                 format_enc_ciphers(c->pair_ciphers));
      }
    }

    /* WPA */
    else if (c->wpa_version) {
      for (i = 0, n = 0; i < 3; i++)
        if (c->wpa_version & (1 << i))
          n++;

      if (n > 1)
        pos += sprintf(pos, "mixed ");

      for (i = 0; i < 3; i++)
        if (c->wpa_version & (1 << i)) {
          if (i)
            pos += sprintf(pos, "WPA%d/", i + 1);
          else
            pos += sprintf(pos, "WPA/");
        }

      pos--;

      sprintf(pos, " %s (%s)",
              format_enc_suites(c->auth_suites),
              format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
    } else {
      snprintf(buf, sizeof(buf), "none");
    }
  } else {
    snprintf(buf, sizeof(buf), "none");
  }

  return buf;
}

static char *format_hwmodes(int modes) {
  static char buf[32] = "802.11";

  if (iwinfo_format_hwmodes(modes, buf + 6, sizeof(buf) - 6) < 1)
    snprintf(buf, sizeof(buf), "unknown");

  return buf;
}

static char *format_assocrate(struct iwinfo_rate_entry *r) {
  static char buf[80];
  char *p = buf;
  int l = sizeof(buf);

  if (r->rate <= 0) {
    snprintf(buf, sizeof(buf), "unknown");
  } else {
    p += snprintf(p, l, "%s", format_rate(r->rate));
    l = sizeof(buf) - (p - buf);

    if (r->is_ht) {
      p += snprintf(p, l, ", MCS %d, %dMHz", r->mcs, r->mhz);
      l = sizeof(buf) - (p - buf);
    } else if (r->is_vht) {
      p += snprintf(p, l, ", VHT-MCS %d, %dMHz", r->mcs, r->mhz);
      l = sizeof(buf) - (p - buf);

      if (r->nss) {
        p += snprintf(p, l, ", VHT-NSS %d", r->nss);
        l = sizeof(buf) - (p - buf);
      }
    } else if (r->is_he) {
      p += snprintf(p, l, ", HE-MCS %d, %dMHz", r->mcs, r->mhz);
      l = sizeof(buf) - (p - buf);

      p += snprintf(p, l, ", HE-NSS %d", r->nss);
      l = sizeof(buf) - (p - buf);

      p += snprintf(p, l, ", HE-GI %d", r->he_gi);
      l = sizeof(buf) - (p - buf);

      p += snprintf(p, l, ", HE-DCM %d", r->he_dcm);
      l = sizeof(buf) - (p - buf);
    }
  }

  return buf;
}

static const char *format_chan_width(bool vht, uint8_t width) {
  if (!vht && width < ARRAY_SIZE(ht_chan_width))
    switch (ht_chan_width[width]) {
    case 20:
      return "20 MHz";
    case 2040:
      return "40 MHz or higher";
    }

  if (vht && width < ARRAY_SIZE(vht_chan_width))
    switch (vht_chan_width[width]) {
    case 40:
      return "20 or 40 MHz";
    case 80:
      return "80 MHz";
    case 8080:
      return "80+80 MHz";
    case 160:
      return "160 MHz";
    }

  return "unknown";
}

static const char *print_type(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  const char *type = iwinfo_type();
  return type ? type : "unknown";
}

static char *print_hardware_id(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  static char buf[20];
  struct iwinfo_hardware_id ids;

  if (!iw->hardware_id(s, ifname, (char *)&ids)) {
    if (strlen(ids.compatible) > 0)
      snprintf(buf, sizeof(buf), "embedded");
    else if (ids.vendor_id == 0 && ids.device_id == 0 &&
             ids.subsystem_vendor_id != 0 && ids.subsystem_device_id != 0)
      snprintf(buf, sizeof(buf), "USB %04X:%04X",
               ids.subsystem_vendor_id, ids.subsystem_device_id);
    else
      snprintf(buf, sizeof(buf), "%04X:%04X %04X:%04X",
               ids.vendor_id, ids.device_id,
               ids.subsystem_vendor_id, ids.subsystem_device_id);
  } else {
    snprintf(buf, sizeof(buf), "unknown");
  }

  return buf;
}

static char *print_hardware_name(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  static char buf[128];

  if (iw->hardware_name(s, ifname, buf))
    snprintf(buf, sizeof(buf), "unknown");

  return buf;
}

static char *print_txpower_offset(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int off;
  static char buf[12];

  if (iw->txpower_offset(s, ifname, &off))
    snprintf(buf, sizeof(buf), "unknown");
  else if (off != 0)
    snprintf(buf, sizeof(buf), "%d dB", off);
  else
    snprintf(buf, sizeof(buf), "none");

  return buf;
}

static char *print_frequency_offset(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int off;
  static char buf[12];

  if (iw->frequency_offset(s, ifname, &off))
    snprintf(buf, sizeof(buf), "unknown");
  else if (off != 0)
    snprintf(buf, sizeof(buf), "%.3f GHz", ((float)off / 1000.0));
  else
    snprintf(buf, sizeof(buf), "none");

  return buf;
}

static char *print_ssid(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  char buf[IWINFO_ESSID_MAX_SIZE + 1] = {0};

  if (iw->ssid(s, ifname, buf))
    memset(buf, 0, sizeof(buf));

  return format_ssid(buf);
}

static char *print_bssid(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  static char buf[18] = {0};

  if (iw->bssid(s, ifname, buf))
    snprintf(buf, sizeof(buf), "00:00:00:00:00:00");

  return buf;
}

static char *print_mode(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int mode;
  static char buf[128];

  if (iw->mode(s, ifname, &mode))
    mode = IWINFO_OPMODE_UNKNOWN;

  snprintf(buf, sizeof(buf), "%s", IWINFO_OPMODE_NAMES[mode]);

  return buf;
}

static char *print_channel(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int ch;
  if (iw->channel(s, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_center_chan1(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int ch;
  if (iw->center_chan1(s, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_center_chan2(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int ch;
  if (iw->center_chan2(s, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_frequency(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int freq;
  if (iw->frequency(s, ifname, &freq))
    freq = -1;

  return format_frequency(freq);
}

static char *print_txpower(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int pwr, off;
  if (iw->txpower_offset(s, ifname, &off))
    off = 0;

  if (iw->txpower(s, ifname, &pwr))
    pwr = -1;
  else
    pwr += off;

  return format_txpower(pwr);
}

static char *print_quality(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int qual;
  if (iw->quality(s, ifname, &qual))
    qual = -1;

  return format_quality(qual);
}

static char *print_quality_max(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int qmax;
  if (iw->quality_max(s, ifname, &qmax))
    qmax = -1;

  return format_quality_max(qmax);
}

static char *print_signal(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int sig;
  if (iw->signal(s, ifname, &sig))
    sig = 0;

  return format_signal(sig);
}

static char *print_noise(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int noise;
  if (iw->noise(s, ifname, &noise))
    noise = 0;

  return format_noise(noise);
}

static char *print_rate(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int rate;
  if (iw->bitrate(s, ifname, &rate))
    rate = -1;

  return format_rate(rate);
}

static char *print_encryption(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  struct iwinfo_crypto_entry c = {0};
  if (iw->encryption(s, ifname, (char *)&c))
    return format_encryption(NULL);

  return format_encryption(&c);
}

static char *print_hwmodes(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int modes;
  if (iw->hwmodelist(s, ifname, &modes))
    modes = -1;

  return format_hwmodes(modes);
}

static const char *print_htmode(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int mode;
  const char *name;
  if (iw->htmode(s, ifname, &mode))
    mode = -1;

  name = iwinfo_htmode_name(mode);
  if (name)
    return name;

  return "unknown";
}

static char *print_mbssid_supp(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int supp;
  static char buf[4];

  if (iw->mbssid_support(s, ifname, &supp))
    snprintf(buf, sizeof(buf), "no");
  else
    snprintf(buf, sizeof(buf), "%s", supp ? "yes" : "no");

  return buf;
}

static char *print_phyname(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  static char buf[32];

  if (!iw->phyname(s, ifname, buf))
    return buf;

  return "?";
}

static void print_info(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  printf("%-9s ESSID: %s\n",
         ifname,
         print_ssid(s, iw, ifname));
  printf("          Access Point: %s\n",
         print_bssid(s, iw, ifname));
  printf("          Mode: %s  Channel: %s (%s)  HT Mode: %s\n",
         print_mode(s, iw, ifname),
         print_channel(s, iw, ifname),
         print_frequency(s, iw, ifname),
         print_htmode(s, iw, ifname));
  if (iw->center_chan1 != NULL) {
    printf("          Center Channel 1: %s",
           print_center_chan1(s, iw, ifname));
    printf(" 2: %s\n", print_center_chan2(s, iw, ifname));
  }
  printf("          Tx-Power: %s  Link Quality: %s/%s\n",
         print_txpower(s, iw, ifname),
         print_quality(s, iw, ifname),
         print_quality_max(s, iw, ifname));
  printf("          Signal: %s  Noise: %s\n",
         print_signal(s, iw, ifname),
         print_noise(s, iw, ifname));
  printf("          Bit Rate: %s\n",
         print_rate(s, iw, ifname));
  printf("          Encryption: %s\n",
         print_encryption(s, iw, ifname));
  printf("          Type: %s  HW Mode(s): %s\n",
         print_type(s, iw, ifname),
         print_hwmodes(s, iw, ifname));
  printf("          Hardware: %s [%s]\n",
         print_hardware_id(s, iw, ifname),
         print_hardware_name(s, iw, ifname));
  printf("          TX power offset: %s\n",
         print_txpower_offset(s, iw, ifname));
  printf("          Frequency offset: %s\n",
         print_frequency_offset(s, iw, ifname));
  printf("          Supports VAPs: %s  PHY name: %s\n",
         print_mbssid_supp(s, iw, ifname),
         print_phyname(s, iw, ifname));
}

static void print_scanlist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int i, x, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_scanlist_entry *e;

  if (iw->scanlist(s, ifname, buf, &len)) {
    printf("Scanning not possible\n\n");
    return;
  } else if (len <= 0) {
    printf("No scan results\n\n");
    return;
  }

  for (i = 0, x = 1; i < len; i += sizeof(struct iwinfo_scanlist_entry), x++) {
    e = (struct iwinfo_scanlist_entry *)&buf[i];

    printf("Cell %02d - Address: %s\n",
           x,
           format_bssid(e->mac));
    printf("          ESSID: %s\n",
           format_ssid(e->ssid));
    printf("          Mode: %s  Frequency: %s  Band: %s  Channel: %s\n",
           IWINFO_OPMODE_NAMES[e->mode],
           format_frequency(e->mhz),
           format_band(e->band),
           format_channel(e->channel));
    printf("          Signal: %s  Quality: %s/%s\n",
           format_signal(e->signal - 0x100),
           format_quality(e->quality),
           format_quality_max(e->quality_max));
    printf("          Encryption: %s\n",
           format_encryption(&e->crypto));
    printf("          HT Operation:\n");
    printf("                    Primary Channel: %d\n",
           e->ht_chan_info.primary_chan);
    printf("                    Secondary Channel Offset: %s\n",
           ht_secondary_offset[e->ht_chan_info.secondary_chan_off]);
    printf("                    Channel Width: %s\n",
           format_chan_width(false, e->ht_chan_info.chan_width));

    if (e->vht_chan_info.center_chan_1) {
      printf("          VHT Operation:\n");
      printf("                    Center Frequency 1: %d\n",
             e->vht_chan_info.center_chan_1);
      printf("                    Center Frequency 2: %d\n",
             e->vht_chan_info.center_chan_2);
      printf("                    Channel Width: %s\n",
             format_chan_width(true, e->vht_chan_info.chan_width));
    }

    printf("\n");
  }
}

static void print_txpwrlist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int len, pwr, off, i;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_txpwrlist_entry *e;

  if (iw->txpwrlist(s, ifname, buf, &len) || len <= 0) {
    printf("No TX power information available\n");
    return;
  }

  if (iw->txpower(s, ifname, &pwr))
    pwr = -1;

  if (iw->txpower_offset(s, ifname, &off))
    off = 0;

  for (i = 0; i < len; i += sizeof(struct iwinfo_txpwrlist_entry)) {
    e = (struct iwinfo_txpwrlist_entry *)&buf[i];

    printf("%s%3d dBm (%4d mW)\n",
           (pwr == e->dbm) ? "*" : " ",
           e->dbm + off,
           iwinfo_dbm2mw(e->dbm + off));
  }
}

static void print_freqlist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int i, len, freq;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_freqlist_entry *e;

  if (iw->freqlist(s, ifname, buf, &len) || len <= 0) {
    printf("No frequency information available\n");
    return;
  }

  if (iw->frequency(s, ifname, &freq))
    freq = -1;

  for (i = 0; i < len; i += sizeof(struct iwinfo_freqlist_entry)) {
    e = (struct iwinfo_freqlist_entry *)&buf[i];

    printf("%s %s (Band: %s, Channel %s) %s\n",
           (freq == e->mhz) ? "*" : " ",
           format_frequency(e->mhz),
           format_band(e->band),
           format_channel(e->channel),
           format_freqflags(e->flags));
  }
}

static void print_assoclist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int i, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_assoclist_entry *e;

  if (iw->assoclist(s, ifname, buf, &len)) {
    printf("No information available\n");
    return;
  } else if (len <= 0) {
    printf("No station connected\n");
    return;
  }

  for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry)) {
    e = (struct iwinfo_assoclist_entry *)&buf[i];

    printf("%s  %s / %s (SNR %d)  %d ms ago\n",
           format_bssid(e->mac),
           format_signal(e->signal),
           format_noise(e->noise),
           (e->signal - e->noise),
           e->inactive);

    printf("	RX: %-38s  %8d Pkts.\n",
           format_assocrate(&e->rx_rate),
           e->rx_packets);

    printf("	TX: %-38s  %8d Pkts.\n",
           format_assocrate(&e->tx_rate),
           e->tx_packets);

    printf("	expected throughput: %s\n\n",
           format_rate(e->thr));
  }
}

static char *lookup_country(char *buf, int len, int iso3166) {
  int i;
  struct iwinfo_country_entry *c;

  for (i = 0; i < len; i += sizeof(struct iwinfo_country_entry)) {
    c = (struct iwinfo_country_entry *)&buf[i];

    if (c->iso3166 == iso3166)
      return c->ccode;
  }

  return NULL;
}

static void print_countrylist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int len;
  char buf[IWINFO_BUFSIZE];
  char *ccode;
  char curcode[3];
  const struct iwinfo_iso3166_label *l;

  if (iw->countrylist(s, ifname, buf, &len)) {
    printf("No country code information available\n");
    return;
  }

  if (iw->country(s, ifname, curcode))
    memset(curcode, 0, sizeof(curcode));

  for (l = IWINFO_ISO3166_NAMES; l->iso3166; l++) {
    if ((ccode = lookup_country(buf, len, l->iso3166)) != NULL) {
      printf("%s %4s	%c%c\n",
             strncmp(ccode, curcode, 2) ? " " : "*",
             ccode, (l->iso3166 / 256), (l->iso3166 % 256));
    }
  }
}

static void print_htmodelist(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *ifname) {
  int i, htmodes = 0;

  if (iw->htmodelist(s, ifname, &htmodes)) {
    printf("No HT mode information available\n");
    return;
  }

  for (i = 0; i < IWINFO_HTMODE_COUNT; i++)
    if (htmodes & (1 << i))
      printf("%s ", IWINFO_HTMODE_NAMES[i]);

  printf("\n");
}

static void lookup_phy(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *section) {
  char buf[IWINFO_BUFSIZE];

  if (!iw->lookup_phy) {
    fprintf(stderr, "Not supported\n");
    return;
  }

  if (iw->lookup_phy(s, section, buf)) {
    fprintf(stderr, "Phy not found\n");
    return;
  }

  printf("%s\n", buf);
}

static void lookup_path(nl80211_state_t *s, const struct iwinfo_ops *iw, const char *phy) {
  const char *path;

  if (!iw->phy_path || iw->phy_path(s, phy, &path) || !path)
    return;

  printf("%s\n", path);
}

int main(int argc, char **argv) {
  int i, rv = 0;
  char *p;
  const struct iwinfo_ops *iw;
  nl80211_state_t *s;
  glob_t globbuf;

  if (argc > 1 && argc < 3) {
    fprintf(stderr,
            "Usage:\n"
            "	iwinfo <device> info\n"
            "	iwinfo <device> scan\n"
            "	iwinfo <device> txpowerlist\n"
            "	iwinfo <device> freqlist\n"
            "	iwinfo <device> assoclist\n"
            "	iwinfo <device> countrylist\n"
            "	iwinfo <device> htmodelist\n"
            "	iwinfo <backend> phyname <section>\n");

    return 1;
  }

  if (argc == 1) {
    glob("/sys/class/net/*", 0, NULL, &globbuf);

    for (i = 0; i < globbuf.gl_pathc; i++) {
      p = strrchr(globbuf.gl_pathv[i], '/');

      if (!p)
        continue;

      iw = iwinfo_backend(++p);
      s = iw->init();

      if (!s)
        continue;

      if(!iw->probe(s, p)) continue;

      print_info(s, iw, p);
      printf("\n");
    }

    globfree(&globbuf);
    return 0;
  }

  if (argc > 3) {
    iw = iwinfo_backend_by_name();
    s = iw->init();

    if (!s) {
      fprintf(stderr, "failed to init wireless backend: %s\n", argv[1]);
      rv = 1;
    } else {
      if (!strcmp(argv[2], "path")) {
        lookup_path(s, iw, argv[3]);
        return 0;
      }
      switch (argv[2][0]) {
      case 'p':
        lookup_phy(s, iw, argv[3]);
        break;

      default:
        fprintf(stderr, "Unknown command: %s\n", argv[2]);
        rv = 1;
      }
    }
  } else {
    iw = iwinfo_backend();
    s = iw->init();

    if (!s) {
      fprintf(stderr, "No such wireless device: %s\n", argv[1]);
      rv = 1;
    } else {
      for (i = 2; i < argc; i++) {
        switch (argv[i][0]) {
        case 'i':
          print_info(s, iw, argv[1]);
          break;

        case 's':
          print_scanlist(s, iw, argv[1]);
          break;

        case 't':
          print_txpwrlist(s, iw, argv[1]);
          break;

        case 'f':
          print_freqlist(s, iw, argv[1]);
          break;

        case 'a':
          print_assoclist(s, iw, argv[1]);
          break;

        case 'c':
          print_countrylist(s, iw, argv[1]);
          break;

        case 'h':
          print_htmodelist(s, iw, argv[1]);
          break;

        default:
          fprintf(stderr, "Unknown command: %s\n", argv[i]);
          rv = 1;
        }
      }
    }
  }

  iwinfo_deinit(s);

  return rv;
}
