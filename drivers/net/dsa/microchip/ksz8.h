/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Microchip KSZ8863 series register access through SMI
 *
 * Copyright (C) 2019 Pengutronix, Michael Grzeschik <kernel@pengutronix.de>
 */

#ifndef __KSZ8XXX_H
#define __KSZ8XXX_H

struct ksz_regs {
	int ind_ctrl_0;
	int ind_data_8;
	int ind_data_check;
	int ind_data_hi;
	int ind_data_lo;
	int ind_mib_check;
	int p_force_ctrl;
	int p_link_status;
	int p_local_ctrl;
	int p_neg_restart_ctrl;
	int p_remote_status;
	int p_speed_status;
	int s_tail_tag_ctrl;
};

struct ksz_masks {
	int port_802_1p_remapping;
	int sw_tail_tag_enable;
	int mib_counter_overflow;
	int mib_counter_valid;
	int vlan_table_fid;
	int vlan_table_membership;
	int vlan_table_valid;
	int static_mac_table_valid;
	int static_mac_table_use_fid;
	int static_mac_table_fid;
	int static_mac_table_override;
	int static_mac_table_fwd_ports;
	int dynamic_mac_table_entries_h;
	int dynamic_mac_table_mac_empty;
	int dynamic_mac_table_not_ready;
	int dynamic_mac_table_entries;
	int dynamic_mac_table_fid;
	int dynamic_mac_table_src_port;
	int dynamic_mac_table_timestamp;
};

struct ksz_shifts {
	int vlan_table_membership;
	int vlan_table;
	int static_mac_fwd_ports;
	int static_mac_fid;
	int dynamic_mac_entries_h;
	int dynamic_mac_entries;
	int dynamic_mac_fid;
	int dynamic_mac_timestamp;
	int dynamic_mac_src_port;
};

struct ksz8 {
	struct ksz_regs *regs;
	struct ksz_masks *masks;
	struct ksz_shifts *shifts;
	void *priv;
};

#endif
