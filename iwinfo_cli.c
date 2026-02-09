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
#include <stdbool.h>

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

static const char *print_type(iwinfo_t *iw, const char *ifname) {
  const char *type = iwinfo_type();
  return type ? type : "unknown";
}

static char *print_hardware_id(iwinfo_t *iw, const char *ifname) {
  static char buf[20];
  struct iwinfo_hardware_id ids;

  if (!iw->iw->hardware_id(iw, ifname, (char *)&ids)) {
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

static char *print_hardware_name(iwinfo_t *iw, const char *ifname) {
  static char buf[128];

  if (iw->iw->hardware_name(iw, ifname, buf))
    snprintf(buf, sizeof(buf), "unknown");

  return buf;
}

static char *print_txpower_offset(iwinfo_t *iw, const char *ifname) {
  int off;
  static char buf[12];

  if (iw->iw->txpower_offset(iw, ifname, &off))
    snprintf(buf, sizeof(buf), "unknown");
  else if (off != 0)
    snprintf(buf, sizeof(buf), "%d dB", off);
  else
    snprintf(buf, sizeof(buf), "none");

  return buf;
}

static char *print_frequency_offset(iwinfo_t *iw, const char *ifname) {
  int off;
  static char buf[12];

  if (iw->iw->frequency_offset(iw, ifname, &off))
    snprintf(buf, sizeof(buf), "unknown");
  else if (off != 0)
    snprintf(buf, sizeof(buf), "%.3f GHz", ((float)off / 1000.0));
  else
    snprintf(buf, sizeof(buf), "none");

  return buf;
}

static char *print_ssid(iwinfo_t *iw, const char *ifname) {
  char buf[IWINFO_ESSID_MAX_SIZE + 1] = {0};

  if (iw->iw->ssid(iw, ifname, buf))
    memset(buf, 0, sizeof(buf));

  return format_ssid(buf);
}

static char *print_bssid(iwinfo_t *iw, const char *ifname) {
  static char buf[18] = {0};

  if (iw->iw->bssid(iw, ifname, buf))
    snprintf(buf, sizeof(buf), "00:00:00:00:00:00");

  return buf;
}

static char *print_mode(iwinfo_t *iw, const char *ifname) {
  int mode;
  static char buf[128];

  if (iw->iw->mode(iw, ifname, &mode))
    mode = IWINFO_OPMODE_UNKNOWN;

  snprintf(buf, sizeof(buf), "%s", IWINFO_OPMODE_NAMES[mode]);

  return buf;
}

static char *print_channel(iwinfo_t *iw, const char *ifname) {
  int ch;
  if (iw->iw->channel(iw, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_center_chan1(iwinfo_t *iw, const char *ifname) {
  int ch;
  if (iw->iw->center_chan1(iw, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_center_chan2(iwinfo_t *iw, const char *ifname) {
  int ch;
  if (iw->iw->center_chan2(iw, ifname, &ch))
    ch = -1;

  return format_channel(ch);
}

static char *print_frequency(iwinfo_t *iw, const char *ifname) {
  int freq;
  if (iw->iw->frequency(iw, ifname, &freq))
    freq = -1;

  return format_frequency(freq);
}

static char *print_txpower(iwinfo_t *iw, const char *ifname) {
  int pwr, off;
  if (iw->iw->txpower_offset(iw, ifname, &off))
    off = 0;

  if (iw->iw->txpower(iw, ifname, &pwr))
    pwr = -1;
  else
    pwr += off;

  return format_txpower(pwr);
}

static char *print_quality(iwinfo_t *iw, const char *ifname) {
  int qual;
  if (iw->iw->quality(iw, ifname, &qual))
    qual = -1;

  return format_quality(qual);
}

static char *print_quality_max(iwinfo_t *iw, const char *ifname) {
  int qmax;
  if (iw->iw->quality_max(iw, ifname, &qmax))
    qmax = -1;

  return format_quality_max(qmax);
}

static char *print_signal(iwinfo_t *iw, const char *ifname) {
  int sig;
  if (iw->iw->signal(iw, ifname, &sig))
    sig = 0;

  return format_signal(sig);
}

static char *print_noise(iwinfo_t *iw, const char *ifname) {
  int noise;
  if (iw->iw->noise(iw, ifname, &noise))
    noise = 0;

  return format_noise(noise);
}

static char *print_rate(iwinfo_t *iw, const char *ifname) {
  int rate;
  if (iw->iw->bitrate(iw, ifname, &rate))
    rate = -1;

  return format_rate(rate);
}

static char *print_encryption(iwinfo_t *iw, const char *ifname) {
  struct iwinfo_crypto_entry c = {0};
  if (iw->iw->encryption(iw, ifname, (char *)&c))
    return format_encryption(NULL);

  return format_encryption(&c);
}

static char *print_hwmodes(iwinfo_t *iw, const char *ifname) {
  int modes;
  if (iw->iw->hwmodelist(iw, ifname, &modes))
    modes = -1;

  return format_hwmodes(modes);
}

static const char *print_htmode(iwinfo_t *iw, const char *ifname) {
  int mode;
  const char *name;
  if (iw->iw->htmode(iw, ifname, &mode))
    mode = -1;

  name = iwinfo_htmode_name(mode);
  if (name)
    return name;

  return "unknown";
}

static char *print_mbssid_supp(iwinfo_t *iw, const char *ifname) {
  int supp;
  static char buf[4];

  if (iw->iw->mbssid_support(iw, ifname, &supp))
    snprintf(buf, sizeof(buf), "no");
  else
    snprintf(buf, sizeof(buf), "%s", supp ? "yes" : "no");

  return buf;
}

static char *print_phyname(iwinfo_t *iw, const char *ifname) {
  static char buf[32];

  if (!iw->iw->phyname(iw, ifname, buf))
    return buf;

  return "?";
}

static void print_info(iwinfo_t *iw, const char *ifname) {
  printf("%-9s ESSID: %s\n",
         ifname,
         print_ssid(iw, ifname));
  printf("          Access Point: %s\n",
         print_bssid(iw, ifname));
  printf("          Mode: %s  Channel: %s (%s)  HT Mode: %s\n",
         print_mode(iw, ifname),
         print_channel(iw, ifname),
         print_frequency(iw, ifname),
         print_htmode(iw, ifname));
  if (iw->iw->center_chan1 != NULL) {
    printf("          Center Channel 1: %s",
           print_center_chan1(iw, ifname));
    printf(" 2: %s\n", print_center_chan2(iw, ifname));
  }
  printf("          Tx-Power: %s  Link Quality: %s/%s\n",
         print_txpower(iw, ifname),
         print_quality(iw, ifname),
         print_quality_max(iw, ifname));
  printf("          Signal: %s  Noise: %s\n",
         print_signal(iw, ifname),
         print_noise(iw, ifname));
  printf("          Bit Rate: %s\n",
         print_rate(iw, ifname));
  printf("          Encryption: %s\n",
         print_encryption(iw, ifname));
  printf("          Type: %s  HW Mode(s): %s\n",
         print_type(iw, ifname),
         print_hwmodes(iw, ifname));
  printf("          Hardware: %s [%s]\n",
         print_hardware_id(iw, ifname),
         print_hardware_name(iw, ifname));
  printf("          TX power offset: %s\n",
         print_txpower_offset(iw, ifname));
  printf("          Frequency offset: %s\n",
         print_frequency_offset(iw, ifname));
  printf("          Supports VAPs: %s  PHY name: %s\n",
         print_mbssid_supp(iw, ifname),
         print_phyname(iw, ifname));
}

static void print_scanlist(iwinfo_t *iw, const char *ifname) {
  int i, x, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_scanlist_entry *e;

  if (iw->iw->scanlist(iw, ifname, buf, &len)) {
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

static void print_scan2(iwinfo_t *iw, const char *ifname, int duration, int freq, int duration_mandatory) {
  int i, x, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_scanlist_entry *e;

  if (!iw->iw->scan_trigger || !iw->iw->scan_get) {
    printf("scan2 not supported\n\n");
    return;
  }

  /* Trigger scan with parameters */
  if (iw->iw->scan_trigger(iw, ifname, duration, freq, duration_mandatory)) {
    printf("Scanning not possible\n\n");
    return;
  }

  /* Get scan results */
  if (iw->iw->scan_get(iw, ifname, buf, &len)) {
    printf("Failed to get scan results\n\n");
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

static void print_txpwrlist(iwinfo_t *iw, const char *ifname) {
  int len, pwr, off, i;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_txpwrlist_entry *e;

  if (iw->iw->txpwrlist(iw, ifname, buf, &len) || len <= 0) {
    printf("No TX power information available\n");
    return;
  }

  if (iw->iw->txpower(iw, ifname, &pwr))
    pwr = -1;

  if (iw->iw->txpower_offset(iw, ifname, &off))
    off = 0;

  for (i = 0; i < len; i += sizeof(struct iwinfo_txpwrlist_entry)) {
    e = (struct iwinfo_txpwrlist_entry *)&buf[i];

    printf("%s%3d dBm (%4d mW)\n",
           (pwr == e->dbm) ? "*" : " ",
           e->dbm + off,
           iwinfo_dbm2mw(e->dbm + off));
  }
}

static void print_freqlist(iwinfo_t *iw, const char *ifname) {
  int i, len, freq;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_freqlist_entry *e;

  if (iw->iw->freqlist(iw, ifname, buf, &len) || len <= 0) {
    printf("No frequency information available\n");
    return;
  }

  if (iw->iw->frequency(iw, ifname, &freq))
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

static void print_assoclist(iwinfo_t *iw, const char *ifname) {
  int i, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_assoclist_entry *e;

  if (iw->iw->assoclist(iw, ifname, buf, &len)) {
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

    printf("	expected throughput: %s\n",
           format_rate(e->thr));

    if (e->tx_duration)
        printf("    TX Duration: %lu us\n", (unsigned long)e->tx_duration);
    if (e->rx_duration)
        printf("    RX Duration: %lu us\n", (unsigned long)e->rx_duration);
    if (e->airtime_weight)
        printf("    Airtime Weight: %u\n", e->airtime_weight);

    printf("\n");
  }
}

static void print_station_dump(iwinfo_t *iw, const char *ifname, const char *mac) {
  struct iwinfo_assoclist_entry e;
  uint8_t mac_bin[6];

  if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &mac_bin[0], &mac_bin[1], &mac_bin[2],
             &mac_bin[3], &mac_bin[4], &mac_bin[5]) != 6) {
    printf("Invalid MAC address\n");
    return;
  }

  if (!iw->iw->station_dump || iw->iw->station_dump(iw, ifname, mac_bin, &e)) {
    printf("No station information available\n");
    return;
  }

  printf("%s  %s / %s (SNR %d)  %d ms ago\n",
         format_bssid(e.mac),
         format_signal(e.signal),
         format_noise(e.noise),
         (e.signal - e.noise),
         e.inactive);

  printf("	RX: %-38s  %8d Pkts.\n",
         format_assocrate(&e.rx_rate),
         e.rx_packets);

  printf("	TX: %-38s  %8d Pkts.\n",
         format_assocrate(&e.tx_rate),
         e.tx_packets);

  printf("	expected throughput: %s\n",
         format_rate(e.thr));

  if (e.tx_duration)
      printf("    TX Duration: %lu us\n", (unsigned long)e.tx_duration);
  if (e.rx_duration)
      printf("    RX Duration: %lu us\n", (unsigned long)e.rx_duration);
  if (e.airtime_weight)
      printf("    Airtime Weight: %u\n", e.airtime_weight);
}

static void print_airtime_survey(iwinfo_t *iw, const char *ifname) {
  struct iwinfo_airtime_entry e;

  if (!iw->iw->airtime_survey || iw->iw->airtime_survey(iw, ifname, &e)) {
    printf("No airtime survey information available\n");
    return;
  }

  printf("Airtime Survey:\n");
  printf("  Active: %u%%\n", e.active);
  printf("  Busy:   %u%%\n", e.busy);
  printf("  TX:     %u%%\n", e.tx);
  printf("  RX:     %u%%\n", e.rx);
  printf("  Other:  %u%%\n", e.other);
  printf("  Interf: %u%%\n", e.interference);
  printf("  Noise:  %s\n", format_noise(e.noise));
}

static void print_airtime_station(iwinfo_t *iw, const char *ifname, const char *mac) {
  int i, len;
  char buf[IWINFO_BUFSIZE];
  struct iwinfo_airtime_entry *e;
  uint8_t mac_bin[6] = {0};

  if (!iw->iw->airtime_station) {
      printf("Function not supported\n");
      return;
  }

  len = IWINFO_BUFSIZE;

  if (mac) {
      if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac_bin[0], &mac_bin[1], &mac_bin[2],
                 &mac_bin[3], &mac_bin[4], &mac_bin[5]) != 6) {
          printf("Invalid MAC address\n");
          return;
      }
      
      if (iw->iw->airtime_station(iw, ifname, mac_bin, buf, &len)) {
          printf("No airtime station information available\n");
          return;
      }
  } else {
      if (iw->iw->airtime_station(iw, ifname, NULL, buf, &len)) {
          printf("No airtime station information available\n");
          return;
      }
  }

  if (len <= 0) {
      printf("No stations found\n");
      return;
  }

  for (i = 0; i < len; i += sizeof(struct iwinfo_airtime_entry)) {
      e = (struct iwinfo_airtime_entry *)&buf[i];
      printf("Station %s Airtime:\n", format_bssid(e->mac));
      printf("  Active: %u%%\n", e->active);
      printf("  Busy:   %u%%\n", e->busy);
      printf("  TX:     %u%%\n", e->tx);
      printf("  RX:     %u%%\n", e->rx);
      printf("  Other:  %u%%\n", e->other);
      printf("  Interf: %u%%\n", e->interference);
      printf("  Signal: %s / %s (SNR %d)\n",
             format_signal(e->signal),
             format_noise(e->noise),
             (e->signal - e->noise));
      printf("  RX Rate: %s\n", format_assocrate(&e->rx_rate));
      printf("  TX Rate: %s\n", format_assocrate(&e->tx_rate));
      printf("\n");
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

static void print_countrylist(iwinfo_t *iw, const char *ifname) {
  int len;
  char buf[IWINFO_BUFSIZE];
  char *ccode;
  char curcode[3];
  const struct iwinfo_iso3166_label *l;

  if (iw->iw->countrylist(iw, ifname, buf, &len)) {
    printf("No country code information available\n");
    return;
  }

  if (iw->iw->country(iw, ifname, curcode))
    memset(curcode, 0, sizeof(curcode));

  for (l = IWINFO_ISO3166_NAMES; l->iso3166; l++) {
    if ((ccode = lookup_country(buf, len, l->iso3166)) != NULL) {
      printf("%s %4s	%c%c\n",
             strncmp(ccode, curcode, 2) ? " " : "*",
             ccode, (l->iso3166 / 256), (l->iso3166 % 256));
    }
  }
}

static void print_htmodelist(iwinfo_t *iw, const char *ifname) {
  int i, htmodes = 0;

  if (iw->iw->htmodelist(iw, ifname, &htmodes)) {
    printf("No HT mode information available\n");
    return;
  }

  for (i = 0; i < IWINFO_HTMODE_COUNT; i++)
    if (htmodes & (1 << i))
      printf("%s ", IWINFO_HTMODE_NAMES[i]);

  printf("\n");
}

static void lookup_phy(iwinfo_t *iw, const char *section) {
  char buf[IWINFO_BUFSIZE];

  if (!iw->iw->lookup_phy) {
    fprintf(stderr, "Not supported\n");
    return;
  }

  if (iw->iw->lookup_phy(iw, section, buf)) {
    fprintf(stderr, "Phy not found\n");
    return;
  }

  printf("%s\n", buf);
}

static void lookup_path(iwinfo_t *iw, const char *phy) {
  const char *path;

  if (!iw->iw->phy_path || iw->iw->phy_path(iw, phy, &path) || !path)
    return;

  printf("%s\n", path);
}

/* cli arguments parse macro and functions */
#define NEXT_ARG()                                                             \
  do {                                                                         \
    argv++;                                                                    \
    if (--argc <= 0)                                                           \
      incomplete_command();                                                    \
  } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREV_ARG()                                                             \
  do {                                                                         \
    argv--;                                                                    \
    argc++;                                                                    \
  } while (0)

/**
 * @brief print message and exit with code -1
 *
 */
static void incomplete_command(void) {
  fprintf(stdout, "Command line is not complete. Try -h or --help\n");
  exit(-1);
}

/**
 * @brief check if 'prefix' matches string
 *
 * @param prefix
 * @param string
 * @return true if 'prefix' is a not empty prefix of 'string'
 * @return false
 */
static bool matches(const char *prefix, const char *string) {
  if (!*prefix)
    return false;
  while (*string && *prefix == *string) {
    prefix++;
    string++;
  }
  return !*prefix;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage:\n"
          "	%s <device> info\n"
          "	%s <device> scan\n"
          "	%s <device> scan2 <freq> <duration> <duration_mandatory>\n"
          "	%s <device> txpowerlist\n"
          "	%s <device> freqlist\n"
          "	%s <device> assoclist\n"
          "	%s <device> countrylist\n"
          "	%s <device> htmodelist\n"
          "	%s <device> station_dump <mac>\n"
          "	%s <device> airtime_survey\n"
          "	%s <device> airtime_station [mac]\n"
          "	%s <backend> phyname <section>\n"
          "	%s <backend> path <phy>\n",
          argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
  exit(1);
}

int main(int argc, char **argv) {
  int i, rv = 0;
  char *p, *argv0;
  iwinfo_t *iw = iwinfo_init();
  if(iw == NULL){
    fprintf(stderr, "failed iwinfo_init\n");
    return 1;
  }
  glob_t globbuf;

  argv0 = *argv;

  if (argc == 1) {
    glob("/sys/class/net/*", 0, NULL, &globbuf);

    for (i = 0; i < globbuf.gl_pathc; i++) {
      p = strrchr(globbuf.gl_pathv[i], '/');

      if (!p) continue;
      if (!iw->iw->probe(iw, ++p)) continue;

      print_info(iw, p);
      printf("\n");
    }

    globfree(&globbuf);
    iwinfo_deinit(iw);
    return 0;
  }

  /* First argument must be interface or backend or help */
  char *ifname = argv[1];
  if (matches(ifname, "-h") || matches(ifname, "--help")) {
    usage(argv0);
  }

  if (!iw->iw->probe(iw, ifname)) {
    fprintf(stderr, "No such wireless device or backend: %s\n", ifname);
    iwinfo_deinit(iw);
    return 1;
  }

  /* Consume the ifname argument */
  NEXT_ARG();

  while (argc > 1) {
    NEXT_ARG();

    if (matches(*argv, "info")) {
      print_info(iw, ifname);
    } else if (matches(*argv, "scan")) {
      print_scanlist(iw, ifname);
    } else if (matches(*argv, "scan2")) {
      int freq = 0, duration = 0, duration_mandatory = 0;
      if (NEXT_ARG_OK()) { NEXT_ARG(); freq = atoi(*argv); }
      if (NEXT_ARG_OK()) { NEXT_ARG(); duration = atoi(*argv); }
      if (NEXT_ARG_OK()) { NEXT_ARG(); duration_mandatory = atoi(*argv); }
      print_scan2(iw, ifname, duration, freq, duration_mandatory);
    } else if (matches(*argv, "txpowerlist")) {
      print_txpwrlist(iw, ifname);
    } else if (matches(*argv, "freqlist")) {
      print_freqlist(iw, ifname);
    } else if (matches(*argv, "assoclist")) {
      print_assoclist(iw, ifname);
    } else if (matches(*argv, "countrylist")) {
      print_countrylist(iw, ifname);
    } else if (matches(*argv, "htmodelist")) {
      print_htmodelist(iw, ifname);
    } else if (matches(*argv, "station_dump")) {
      if (NEXT_ARG_OK()) {
        NEXT_ARG();
        print_station_dump(iw, ifname, *argv);
      } else {
        incomplete_command();
      }
    } else if (matches(*argv, "airtime_survey")) {
      print_airtime_survey(iw, ifname);
    } else if (matches(*argv, "airtime_station")) {
      const char *mac = NULL;
      if (NEXT_ARG_OK()) {
        /* Check if next arg is a MAC or another command */
        argv++;
        if (argc > 1 && strchr(*argv, ':')) {
            mac = *argv;
            argc--;
        } else {
            /* Not a MAC, put it back */
            argv--;
        }
      }
      print_airtime_station(iw, ifname, mac);
    } else if (matches(*argv, "phyname")) {
      if (NEXT_ARG_OK()) {
        NEXT_ARG();
        lookup_phy(iw, *argv);
      } else {
        incomplete_command();
      }
    } else if (matches(*argv, "path")) {
      if (NEXT_ARG_OK()) {
        NEXT_ARG();
        lookup_path(iw, *argv);
      } else {
        incomplete_command();
      }
    } else {
      usage(argv0);
    }
  }

  iwinfo_deinit(iw);
  return rv;
}
