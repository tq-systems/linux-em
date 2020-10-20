// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip KSZ8795 switch driver
 *
 * Copyright (C) 2017 Microchip Technology Inc.
 *	Tristram Ha <Tristram.Ha@microchip.com>
 */

#include <linux/delay.h>
#include <linux/export.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_data/microchip-ksz.h>
#include <linux/phy.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "ksz_common.h"
#include "ksz8795_reg.h"
#include "ksz8863_reg.h"
#include "ksz8.h"

static struct ksz_regs ksz8795_regs = {
	.ind_ctrl_0			= KSZ8795_REG_IND_CTRL_0,
	.ind_data_8			= KSZ8795_REG_IND_DATA_8,
	.ind_data_check			= KSZ8795_REG_IND_DATA_CHECK,
	.ind_data_hi			= KSZ8795_REG_IND_DATA_HI,
	.ind_data_lo			= KSZ8795_REG_IND_DATA_LO,
	.ind_mib_check			= KSZ8795_REG_IND_MIB_CHECK,
	.p_force_ctrl			= KSZ8795_P_FORCE_CTRL,
	.p_link_status			= KSZ8795_P_LINK_STATUS,
	.p_local_ctrl			= KSZ8795_P_LOCAL_CTRL,
	.p_neg_restart_ctrl		= KSZ8795_P_NEG_RESTART_CTRL,
	.p_remote_status		= KSZ8795_P_REMOTE_STATUS,
	.p_speed_status			= KSZ8795_P_SPEED_STATUS,
	.s_tail_tag_ctrl		= KSZ8795_S_TAIL_TAG_CTRL,
};

static struct ksz_masks ksz8795_masks = {
	.port_802_1p_remapping		= KSZ8795_PORT_802_1P_REMAPPING,
	.sw_tail_tag_enable		= KSZ8795_SW_TAIL_TAG_ENABLE,
	.mib_counter_overflow		= KSZ8795_MIB_COUNTER_OVERFLOW,
	.mib_counter_valid		= KSZ8795_MIB_COUNTER_VALID,
	.vlan_table_fid			= KSZ8795_VLAN_TABLE_FID,
	.vlan_table_membership		= KSZ8795_VLAN_TABLE_MEMBERSHIP,
	.vlan_table_valid		= KSZ8795_VLAN_TABLE_VALID,
	.static_mac_table_valid		= KSZ8795_STATIC_MAC_TABLE_VALID,
	.static_mac_table_use_fid	= KSZ8795_STATIC_MAC_TABLE_USE_FID,
	.static_mac_table_fid		= KSZ8795_STATIC_MAC_TABLE_FID,
	.static_mac_table_override	= KSZ8795_STATIC_MAC_TABLE_OVERRIDE,
	.static_mac_table_fwd_ports	= KSZ8795_STATIC_MAC_TABLE_FWD_PORTS,
	.dynamic_mac_table_entries_h	= KSZ8795_DYNAMIC_MAC_TABLE_ENTRIES_H,
	.dynamic_mac_table_mac_empty	= KSZ8795_DYNAMIC_MAC_TABLE_MAC_EMPTY,
	.dynamic_mac_table_not_ready	= KSZ8795_DYNAMIC_MAC_TABLE_NOT_READY,
	.dynamic_mac_table_entries	= KSZ8795_DYNAMIC_MAC_TABLE_ENTRIES,
	.dynamic_mac_table_fid		= KSZ8795_DYNAMIC_MAC_TABLE_FID,
	.dynamic_mac_table_src_port	= KSZ8795_DYNAMIC_MAC_TABLE_SRC_PORT,
	.dynamic_mac_table_timestamp	= KSZ8795_DYNAMIC_MAC_TABLE_TIMESTAMP,
};

static struct ksz_shifts ksz8795_shifts = {
	.vlan_table_membership		= KSZ8795_VLAN_TABLE_MEMBERSHIP_S,
	.vlan_table			= KSZ8795_VLAN_TABLE_S,
	.static_mac_fwd_ports		= KSZ8795_STATIC_MAC_FWD_PORTS_S,
	.static_mac_fid			= KSZ8795_STATIC_MAC_FID_S,
	.dynamic_mac_entries		= KSZ8795_DYNAMIC_MAC_ENTRIES_S,
	.dynamic_mac_fid		= KSZ8795_DYNAMIC_MAC_FID_S,
	.dynamic_mac_timestamp		= KSZ8795_DYNAMIC_MAC_TIMESTAMP_S,
	.dynamic_mac_src_port		= KSZ8795_DYNAMIC_MAC_SRC_PORT_S,
};

static struct ksz_regs ksz8863_regs = {
	.ind_ctrl_0			= KSZ8863_REG_IND_CTRL_0,
	.ind_data_8			= KSZ8863_REG_IND_DATA_8,
	.ind_data_check			= KSZ8863_REG_IND_DATA_CHECK,
	.ind_data_hi			= KSZ8863_REG_IND_DATA_HI,
	.ind_data_lo			= KSZ8863_REG_IND_DATA_LO,
	.ind_mib_check			= KSZ8863_REG_IND_MIB_CHECK,
	.p_force_ctrl			= KSZ8863_P_FORCE_CTRL,
	.p_link_status			= KSZ8863_P_LINK_STATUS,
	.p_local_ctrl			= KSZ8863_P_LOCAL_CTRL,
	.p_neg_restart_ctrl		= KSZ8863_P_NEG_RESTART_CTRL,
	.p_remote_status		= KSZ8863_P_REMOTE_STATUS,
	.p_speed_status			= KSZ8863_P_SPEED_STATUS,
	.s_tail_tag_ctrl		= KSZ8863_S_TAIL_TAG_CTRL,
};

static struct ksz_masks ksz8863_masks = {
	.port_802_1p_remapping		= KSZ8863_PORT_802_1P_REMAPPING,
	.sw_tail_tag_enable		= KSZ8863_SW_TAIL_TAG_ENABLE,
	.mib_counter_overflow		= KSZ8863_MIB_COUNTER_OVERFLOW,
	.mib_counter_valid		= KSZ8863_MIB_COUNTER_VALID,
	.vlan_table_fid			= KSZ8863_VLAN_TABLE_FID,
	.vlan_table_membership		= KSZ8863_VLAN_TABLE_MEMBERSHIP,
	.vlan_table_valid		= KSZ8863_VLAN_TABLE_VALID,
	.static_mac_table_valid		= KSZ8863_STATIC_MAC_TABLE_VALID,
	.static_mac_table_use_fid	= KSZ8863_STATIC_MAC_TABLE_USE_FID,
	.static_mac_table_fid		= KSZ8863_STATIC_MAC_TABLE_FID,
	.static_mac_table_override	= KSZ8863_STATIC_MAC_TABLE_OVERRIDE,
	.static_mac_table_fwd_ports	= KSZ8863_STATIC_MAC_TABLE_FWD_PORTS,
	.dynamic_mac_table_entries_h	= KSZ8863_DYNAMIC_MAC_TABLE_ENTRIES_H,
	.dynamic_mac_table_mac_empty	= KSZ8863_DYNAMIC_MAC_TABLE_MAC_EMPTY,
	.dynamic_mac_table_not_ready	= KSZ8863_DYNAMIC_MAC_TABLE_NOT_READY,
	.dynamic_mac_table_entries	= KSZ8863_DYNAMIC_MAC_TABLE_ENTRIES,
	.dynamic_mac_table_fid		= KSZ8863_DYNAMIC_MAC_TABLE_FID,
	.dynamic_mac_table_src_port	= KSZ8863_DYNAMIC_MAC_TABLE_SRC_PORT,
	.dynamic_mac_table_timestamp	= KSZ8863_DYNAMIC_MAC_TABLE_TIMESTAMP,
};

static struct ksz_shifts ksz8863_shifts = {
	.vlan_table_membership		= KSZ8863_VLAN_TABLE_MEMBERSHIP_S,
	.static_mac_fwd_ports		= KSZ8863_STATIC_MAC_FWD_PORTS_S,
	.static_mac_fid			= KSZ8863_STATIC_MAC_FID_S,
	.dynamic_mac_entries		= KSZ8863_DYNAMIC_MAC_ENTRIES_S,
	.dynamic_mac_fid		= KSZ8863_DYNAMIC_MAC_FID_S,
	.dynamic_mac_timestamp		= KSZ8863_DYNAMIC_MAC_TIMESTAMP_S,
	.dynamic_mac_src_port		= KSZ8863_DYNAMIC_MAC_SRC_PORT_S,
};

static const struct {
	char string[ETH_GSTRING_LEN];
} ksz87xx_mib_names[TOTAL_KSZ8795_COUNTER_NUM] = {
	{ "rx_hi" },
	{ "rx_undersize" },
	{ "rx_fragments" },
	{ "rx_oversize" },
	{ "rx_jabbers" },
	{ "rx_symbol_err" },
	{ "rx_crc_err" },
	{ "rx_align_err" },
	{ "rx_mac_ctrl" },
	{ "rx_pause" },
	{ "rx_bcast" },
	{ "rx_mcast" },
	{ "rx_ucast" },
	{ "rx_64_or_less" },
	{ "rx_65_127" },
	{ "rx_128_255" },
	{ "rx_256_511" },
	{ "rx_512_1023" },
	{ "rx_1024_1522" },
	{ "rx_1523_2000" },
	{ "rx_2001" },
	{ "tx_hi" },
	{ "tx_late_col" },
	{ "tx_pause" },
	{ "tx_bcast" },
	{ "tx_mcast" },
	{ "tx_ucast" },
	{ "tx_deferred" },
	{ "tx_total_col" },
	{ "tx_exc_col" },
	{ "tx_single_col" },
	{ "tx_mult_col" },
	{ "rx_total" },
	{ "tx_total" },
	{ "rx_discards" },
	{ "tx_discards" },
};

static const struct {
	char string[ETH_GSTRING_LEN];
} ksz88xx_mib_names[TOTAL_KSZ8863_COUNTER_NUM] = {
	{ "rx" },
	{ "rx_hi" },
	{ "rx_undersize" },
	{ "rx_fragments" },
	{ "rx_oversize" },
	{ "rx_jabbers" },
	{ "rx_symbol_err" },
	{ "rx_crc_err" },
	{ "rx_align_err" },
	{ "rx_mac_ctrl" },
	{ "rx_pause" },
	{ "rx_bcast" },
	{ "rx_mcast" },
	{ "rx_ucast" },
	{ "rx_64_or_less" },
	{ "rx_65_127" },
	{ "rx_128_255" },
	{ "rx_256_511" },
	{ "rx_512_1023" },
	{ "rx_1024_1522" },
	{ "tx" },
	{ "tx_hi" },
	{ "tx_late_col" },
	{ "tx_pause" },
	{ "tx_bcast" },
	{ "tx_mcast" },
	{ "tx_ucast" },
	{ "tx_deferred" },
	{ "tx_total_col" },
	{ "tx_exc_col" },
	{ "tx_single_col" },
	{ "tx_mult_col" },
	{ "rx_discards" },
	{ "tx_discards" },
};

static void ksz_cfg(struct ksz_device *dev, u32 addr, u8 bits, bool set)
{
	regmap_update_bits(dev->regmap[0], addr, bits, set ? bits : 0);
}

static void ksz_port_cfg(struct ksz_device *dev, int port, int offset, u8 bits,
			 bool set)
{
	regmap_update_bits(dev->regmap[0], PORT_CTRL_ADDR(port, offset),
			   bits, set ? bits : 0);
}

static int ksz_is_87(struct ksz_device *dev)
{
	return (((dev->chip_id) >> 8) == KSZ87_FAMILY_ID);
}

static int ksz_is_88(struct ksz_device *dev)
{
	return (((dev->chip_id) >> 8) == KSZ88_FAMILY_ID);
}

static int ksz8_reset_switch(struct ksz_device *dev)
{
	if (ksz_is_87(dev)) {
		/* reset switch */
		ksz_write8(dev, REG_POWER_MANAGEMENT_1,
			   SW_SOFTWARE_POWER_DOWN << SW_POWER_MANAGEMENT_MODE_S);
		ksz_write8(dev, REG_POWER_MANAGEMENT_1, 0);
	} else {
		/* reset switch */
		ksz_cfg(dev, KSZ8863_REG_SW_RESET,
			KSZ8863_GLOBAL_SOFTWARE_RESET | KSZ8863_PCS_RESET, true);
	}

	return 0;
}

static void ksz8795_set_prio_queue(struct ksz_device *dev, int port, int queue)
{
	u8 hi, lo;

	/* Number of queues can only be 1, 2, or 4. */
	switch (queue) {
	case 4:
	case 3:
		queue = PORT_QUEUE_SPLIT_4;
		break;
	case 2:
		queue = PORT_QUEUE_SPLIT_2;
		break;
	default:
		queue = PORT_QUEUE_SPLIT_1;
	}
	ksz_pread8(dev, port, REG_PORT_CTRL_0, &lo);
	ksz_pread8(dev, port, P_DROP_TAG_CTRL, &hi);
	lo &= ~PORT_QUEUE_SPLIT_L;
	if (queue & PORT_QUEUE_SPLIT_2)
		lo |= PORT_QUEUE_SPLIT_L;
	hi &= ~PORT_QUEUE_SPLIT_H;
	if (queue & PORT_QUEUE_SPLIT_4)
		hi |= PORT_QUEUE_SPLIT_H;
	ksz_pwrite8(dev, port, REG_PORT_CTRL_0, lo);
	ksz_pwrite8(dev, port, P_DROP_TAG_CTRL, hi);

	/* Default is port based for egress rate limit. */
	if (queue != PORT_QUEUE_SPLIT_1)
		ksz_cfg(dev, REG_SW_CTRL_19, SW_OUT_RATE_LIMIT_QUEUE_BASED,
			true);
}

static void ksz8_r_mib_cnt(struct ksz_device *dev, int port, u16 addr, u64 *cnt)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	struct ksz_masks *masks = ksz8->masks;
	u16 ctrl_addr;
	u32 data;
	u8 check;
	int loop;

	ctrl_addr = addr + dev->reg_mib_cnt * port;
	ctrl_addr |= IND_ACC_TABLE(TABLE_MIB | TABLE_READ);

	mutex_lock(&dev->alu_mutex);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);

	/* It is almost guaranteed to always read the valid bit because of
	 * slow SPI speed.
	 */
	for (loop = 2; loop > 0; loop--) {
		ksz_read8(dev, regs->ind_mib_check, &check);

		if (check & masks->mib_counter_valid) {
			ksz_read32(dev, regs->ind_data_lo, &data);
			if (check & masks->mib_counter_overflow)
				*cnt += MIB_COUNTER_VALUE + 1;
			*cnt += data & MIB_COUNTER_VALUE;
			break;
		}
	}
	mutex_unlock(&dev->alu_mutex);
}

static void ksz8795_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			      u64 *dropped, u64 *cnt)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u16 ctrl_addr;
	u32 data;
	u8 check;
	int loop;

	addr -= dev->reg_mib_cnt;
	ctrl_addr = (KSZ8795_MIB_TOTAL_RX_1 - KSZ8795_MIB_TOTAL_RX_0) * port;
	ctrl_addr += addr + KSZ8795_MIB_TOTAL_RX_0;
	ctrl_addr |= IND_ACC_TABLE(TABLE_MIB | TABLE_READ);

	mutex_lock(&dev->alu_mutex);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);

	/* It is almost guaranteed to always read the valid bit because of
	 * slow SPI speed.
	 */
	for (loop = 2; loop > 0; loop--) {
		ksz_read8(dev, regs->ind_mib_check, &check);

		if (check & KSZ8795_MIB_COUNTER_VALID) {
			ksz_read32(dev, regs->ind_data_lo, &data);
			if (addr < 2) {
				u64 total;

				total = check & MIB_TOTAL_BYTES_H;
				total <<= 32;
				*cnt += total;
				*cnt += data;
				if (check & KSZ8795_MIB_COUNTER_OVERFLOW) {
					total = MIB_TOTAL_BYTES_H + 1;
					total <<= 32;
					*cnt += total;
				}
			} else {
				if (check & KSZ8795_MIB_COUNTER_OVERFLOW)
					*cnt += MIB_PACKET_DROPPED + 1;
				*cnt += data & MIB_PACKET_DROPPED;
			}
			break;
		}
	}
	mutex_unlock(&dev->alu_mutex);
}

static void ksz8863_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			      u64 *dropped, u64 *cnt)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u32 *last = (u32 *)dropped;
	u16 ctrl_addr;
	u32 data;
	u32 cur;

	addr -= dev->reg_mib_cnt;
	ctrl_addr = addr ? KSZ8863_MIB_PACKET_DROPPED_TX_0 :
			   KSZ8863_MIB_PACKET_DROPPED_RX_0;
	ctrl_addr += port;
	ctrl_addr |= IND_ACC_TABLE(TABLE_MIB | TABLE_READ);

	mutex_lock(&dev->alu_mutex);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);
	ksz_read32(dev, regs->ind_data_lo, &data);
	mutex_unlock(&dev->alu_mutex);

	data &= MIB_PACKET_DROPPED;
	cur = last[addr];
	if (data != cur) {
		last[addr] = data;
		if (data < cur)
			data += MIB_PACKET_DROPPED + 1;
		data -= cur;
		*cnt += data;
	}
}

static void ksz8_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			   u64 *dropped, u64 *cnt)
{
	if (ksz_is_87(dev)) {
		ksz8795_r_mib_pkt(dev, port, addr, dropped, cnt);
	} else {
		ksz8863_r_mib_pkt(dev, port, addr, dropped, cnt);
	}
}

static void ksz8_freeze_mib(struct ksz_device *dev, int port, bool freeze)
{
	if (!ksz_is_87(dev))
		return;

	/* enable the port for flush/freeze function */
	if (freeze)
		ksz_cfg(dev, REG_SW_CTRL_6, BIT(port), true);
	ksz_cfg(dev, REG_SW_CTRL_6, SW_MIB_COUNTER_FREEZE, freeze);

	/* disable the port after freeze is done */
	if (!freeze)
		ksz_cfg(dev, REG_SW_CTRL_6, BIT(port), false);
}

static void ksz8_port_init_cnt(struct ksz_device *dev, int port)
{
	struct ksz_port_mib *mib = &dev->ports[port].mib;
	u64 *dropped;

	if (ksz_is_87(dev)) {
		/* flush all enabled port MIB counters */
		ksz_cfg(dev, REG_SW_CTRL_6, BIT(port), true);
		ksz_cfg(dev, REG_SW_CTRL_6, SW_MIB_COUNTER_FLUSH, true);
		ksz_cfg(dev, REG_SW_CTRL_6, BIT(port), false);
	}

	mib->cnt_ptr = 0;

	/* Some ports may not have MIB counters before SWITCH_COUNTER_NUM. */
	while (mib->cnt_ptr < dev->reg_mib_cnt) {
		dev->dev_ops->r_mib_cnt(dev, port, mib->cnt_ptr,
					&mib->counters[mib->cnt_ptr]);
		++mib->cnt_ptr;
	}

	/* last one in storage */
	dropped = &mib->counters[dev->mib_cnt];

	/* Some ports may not have MIB counters after SWITCH_COUNTER_NUM. */
	while (mib->cnt_ptr < dev->mib_cnt) {
		dev->dev_ops->r_mib_pkt(dev, port, mib->cnt_ptr,
					dropped, &mib->counters[mib->cnt_ptr]);
		++mib->cnt_ptr;
	}
	mib->cnt_ptr = 0;
	memset(mib->counters, 0, dev->mib_cnt * sizeof(u64));
}

static void ksz8_r_table(struct ksz_device *dev, int table, u16 addr, u64 *data)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u16 ctrl_addr;

	ctrl_addr = IND_ACC_TABLE(table | TABLE_READ) | addr;

	mutex_lock(&dev->alu_mutex);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);
	ksz_read64(dev, regs->ind_data_hi, data);
	mutex_unlock(&dev->alu_mutex);
}

static void ksz8_w_table(struct ksz_device *dev, int table, u16 addr, u64 data)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u16 ctrl_addr;

	ctrl_addr = IND_ACC_TABLE(table) | addr;

	mutex_lock(&dev->alu_mutex);
	ksz_write64(dev, regs->ind_data_hi, data);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);
	mutex_unlock(&dev->alu_mutex);
}

static int ksz8_valid_dyn_entry(struct ksz_device *dev, u8 *data)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	struct ksz_masks *masks = ksz8->masks;
	int timeout = 100;

	do {
		ksz_read8(dev, regs->ind_data_check, data);
		timeout--;
	} while ((*data & masks->dynamic_mac_table_not_ready) && timeout);

	/* Entry is not ready for accessing. */
	if (*data & masks->dynamic_mac_table_not_ready) {
		return -EAGAIN;
	/* Entry is ready for accessing. */
	} else {
		ksz_read8(dev, regs->ind_data_8, data);

		/* There is no valid entry in the table. */
		if (*data & masks->dynamic_mac_table_mac_empty)
			return -ENXIO;
	}
	return 0;
}

static int ksz8_r_dyn_mac_table(struct ksz_device *dev, u16 addr,
				u8 *mac_addr, u8 *fid, u8 *src_port,
				u8 *timestamp, u16 *entries)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_shifts *shifts = ksz8->shifts;
	u32 data_hi, data_lo;
	u16 ctrl_addr;
	u8 data;
	int rc;

	ctrl_addr = IND_ACC_TABLE(TABLE_DYNAMIC_MAC | TABLE_READ) | addr;

	mutex_lock(&dev->alu_mutex);
	ksz_write16(dev, regs->ind_ctrl_0, ctrl_addr);

	rc = ksz8_valid_dyn_entry(dev, &data);
	if (rc == -EAGAIN) {
		if (addr == 0)
			*entries = 0;
	} else if (rc == -ENXIO) {
		*entries = 0;
	/* At least one valid entry in the table. */
	} else {
		u64 buf = 0;
		int cnt;

		ksz_read64(dev, regs->ind_data_hi, &buf);
		data_hi = (u32)(buf >> 32);
		data_lo = (u32)buf;

		/* Check out how many valid entry in the table. */
		cnt = data & masks->dynamic_mac_table_entries_h;
		cnt <<= shifts->dynamic_mac_entries_h;
		cnt |= (data_hi & masks->dynamic_mac_table_entries) >>
			shifts->dynamic_mac_entries;
		*entries = cnt + 1;

		*fid = (data_hi & masks->dynamic_mac_table_fid) >>
			shifts->dynamic_mac_fid;
		*src_port = (data_hi & masks->dynamic_mac_table_src_port) >>
			shifts->dynamic_mac_src_port;
		*timestamp = (data_hi & masks->dynamic_mac_table_timestamp) >>
			shifts->dynamic_mac_timestamp;

		mac_addr[5] = (u8)data_lo;
		mac_addr[4] = (u8)(data_lo >> 8);
		mac_addr[3] = (u8)(data_lo >> 16);
		mac_addr[2] = (u8)(data_lo >> 24);

		mac_addr[1] = (u8)data_hi;
		mac_addr[0] = (u8)(data_hi >> 8);
		rc = 0;
	}
	mutex_unlock(&dev->alu_mutex);

	return rc;
}

static int ksz8_r_sta_mac_table(struct ksz_device *dev, u16 addr,
				struct alu_struct *alu)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_shifts *shifts = ksz8->shifts;
	u32 data_hi, data_lo;
	u64 data;

	ksz8_r_table(dev, TABLE_STATIC_MAC, addr, &data);
	data_hi = data >> 32;
	data_lo = (u32)data;
	if (data_hi & (masks->static_mac_table_valid |
			masks->static_mac_table_override)) {
		alu->mac[5] = (u8)data_lo;
		alu->mac[4] = (u8)(data_lo >> 8);
		alu->mac[3] = (u8)(data_lo >> 16);
		alu->mac[2] = (u8)(data_lo >> 24);
		alu->mac[1] = (u8)data_hi;
		alu->mac[0] = (u8)(data_hi >> 8);
		alu->port_forward =
			(data_hi & masks->static_mac_table_fwd_ports) >>
				shifts->static_mac_fwd_ports;
		alu->is_override =
			(data_hi & masks->static_mac_table_override) ? 1 : 0;
		data_hi >>= 1;
		alu->is_static = true;
		alu->is_use_fid =
			(data_hi & masks->static_mac_table_use_fid) ? 1 : 0;
		alu->fid = (data_hi & masks->static_mac_table_fid) >>
				shifts->static_mac_fid;
		return 0;
	}
	return -ENXIO;
}

static void ksz8_w_sta_mac_table(struct ksz_device *dev, u16 addr,
				 struct alu_struct *alu)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_shifts *shifts = ksz8->shifts;
	u32 data_hi, data_lo;
	u64 data;

	data_lo = ((u32)alu->mac[2] << 24) |
		((u32)alu->mac[3] << 16) |
		((u32)alu->mac[4] << 8) | alu->mac[5];
	data_hi = ((u32)alu->mac[0] << 8) | alu->mac[1];
	data_hi |= (u32)alu->port_forward << shifts->static_mac_fwd_ports;

	if (alu->is_override)
		data_hi |= masks->static_mac_table_override;
	if (alu->is_use_fid) {
		data_hi |= masks->static_mac_table_use_fid;
		data_hi |= (u32)alu->fid << shifts->static_mac_fid;
	}
	if (alu->is_static)
		data_hi |= masks->static_mac_table_valid;
	else
		data_hi &= ~masks->static_mac_table_override;

	data = (u64)data_hi << 32 | data_lo;
	ksz8_w_table(dev, TABLE_STATIC_MAC, addr, data);
}

static void ksz8_from_vlan(struct ksz_device *dev, u32 vlan, u8 *fid,
			   u8 *member, u8 *valid)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_shifts *shifts = ksz8->shifts;

	*fid = vlan & masks->vlan_table_fid;
	*member = (vlan & masks->vlan_table_membership) >>
			shifts->vlan_table_membership;
	*valid = !!(vlan & masks->vlan_table_valid);
}

static void ksz8_to_vlan(struct ksz_device *dev, u8 fid, u8 member, u8 valid,
			 u32 *vlan)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_shifts *shifts = ksz8->shifts;

	*vlan = fid;
	*vlan |= (u16)member << shifts->vlan_table_membership;
	if (valid)
		*vlan |= masks->vlan_table_valid;
}

static void ksz8_r_vlan_entries(struct ksz_device *dev, u16 addr)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_shifts *shifts = ksz8->shifts;
	u64 data;
	int i;

	ksz8_r_table(dev, TABLE_VLAN, addr, &data);
	addr *= dev->port_cnt;
	for (i = 0; i < dev->port_cnt; i++) {
		if (ksz_is_87(dev)) {
			dev->vlan_cache[addr + i].table[0] = (u16)data;
			data >>= shifts->vlan_table;
		} else {
			dev->vlan_cache[addr + i].table[0] = (u32)data;
		}
	}
}

static void ksz8_r_vlan_table(struct ksz_device *dev, u16 vid, u32 *vlan)
{
	u16 addr = vid / dev->port_cnt;
	u64 buf;

	ksz8_r_table(dev, TABLE_VLAN, addr, &buf);
	if (ksz_is_87(dev)) {
		u16 *data = (u16 *)&buf;

		*vlan = data[vid & 3];
	} else {
		*vlan = (u32)buf;
	}
}

static void ksz8_w_vlan_table(struct ksz_device *dev, u16 vid, u32 vlan)
{
	u16 addr = vid / dev->port_cnt;
	u64 buf;

	ksz8_r_table(dev, TABLE_VLAN, addr, &buf);

	if (ksz_is_87(dev)) {
		u16 *data = (u16 *)&buf;

		data[vid & 3] = vlan;
	} else {
		buf = vlan;
	}

	dev->vlan_cache[vid].table[0] = vlan;
	ksz8_w_table(dev, TABLE_VLAN, addr, buf);
}

static void ksz8_r_phy(struct ksz_device *dev, u16 phy, u16 reg, u16 *val)
{
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u8 restart, speed, ctrl, link;
	int processed = true;
	u16 data = 0;
	u8 p = phy;

	switch (reg) {
	case PHY_REG_CTRL:
		ksz_pread8(dev, p, regs->p_neg_restart_ctrl, &restart);
		ksz_pread8(dev, p, regs->p_speed_status, &speed);
		ksz_pread8(dev, p, regs->p_force_ctrl, &ctrl);
		if (restart & PORT_PHY_LOOPBACK)
			data |= PHY_LOOPBACK;
		if (ctrl & PORT_FORCE_100_MBIT)
			data |= PHY_SPEED_100MBIT;
		if (ksz_is_87(dev)) {
			if (!(ctrl & PORT_AUTO_NEG_DISABLE))
				data |= PHY_AUTO_NEG_ENABLE;
		} else {
			if ((ctrl & PORT_AUTO_NEG_ENABLE))
				data |= PHY_AUTO_NEG_ENABLE;
		}
		if (restart & PORT_POWER_DOWN)
			data |= PHY_POWER_DOWN;
		if (restart & PORT_AUTO_NEG_RESTART)
			data |= PHY_AUTO_NEG_RESTART;
		if (ctrl & PORT_FORCE_FULL_DUPLEX)
			data |= PHY_FULL_DUPLEX;
		if (speed & PORT_HP_MDIX)
			data |= PHY_HP_MDIX;
		if (restart & PORT_FORCE_MDIX)
			data |= PHY_FORCE_MDIX;
		if (restart & PORT_AUTO_MDIX_DISABLE)
			data |= PHY_AUTO_MDIX_DISABLE;
		if (restart & PORT_TX_DISABLE)
			data |= PHY_TRANSMIT_DISABLE;
		if (restart & PORT_LED_OFF)
			data |= PHY_LED_DISABLE;
		break;
	case PHY_REG_STATUS:
		ksz_pread8(dev, p, regs->p_link_status, &link);
		data = PHY_100BTX_FD_CAPABLE |
		       PHY_100BTX_CAPABLE |
		       PHY_10BT_FD_CAPABLE |
		       PHY_10BT_CAPABLE |
		       PHY_AUTO_NEG_CAPABLE;
		if (link & PORT_AUTO_NEG_COMPLETE)
			data |= PHY_AUTO_NEG_ACKNOWLEDGE;
		if (link & PORT_STAT_LINK_GOOD)
			data |= PHY_LINK_STATUS;
		break;
	case PHY_REG_ID_1:
		if (ksz_is_87(dev))
			data = KSZ8795_ID_HI;
		else
			data = KSZ8863_ID_HI;
		break;
	case PHY_REG_ID_2:
		if (ksz_is_87(dev))
			data = KSZ8795_ID_LO;
		else
			data = KSZ8863_ID_LO;
		break;
	case PHY_REG_AUTO_NEGOTIATION:
		ksz_pread8(dev, p, regs->p_local_ctrl, &ctrl);
		data = PHY_AUTO_NEG_802_3;
		if (ctrl & PORT_AUTO_NEG_SYM_PAUSE)
			data |= PHY_AUTO_NEG_SYM_PAUSE;
		if (ctrl & PORT_AUTO_NEG_100BTX_FD)
			data |= PHY_AUTO_NEG_100BTX_FD;
		if (ctrl & PORT_AUTO_NEG_100BTX)
			data |= PHY_AUTO_NEG_100BTX;
		if (ctrl & PORT_AUTO_NEG_10BT_FD)
			data |= PHY_AUTO_NEG_10BT_FD;
		if (ctrl & PORT_AUTO_NEG_10BT)
			data |= PHY_AUTO_NEG_10BT;
		break;
	case PHY_REG_REMOTE_CAPABILITY:
		ksz_pread8(dev, p, regs->p_remote_status, &link);
		data = PHY_AUTO_NEG_802_3;
		if (link & PORT_REMOTE_SYM_PAUSE)
			data |= PHY_AUTO_NEG_SYM_PAUSE;
		if (link & PORT_REMOTE_100BTX_FD)
			data |= PHY_AUTO_NEG_100BTX_FD;
		if (link & PORT_REMOTE_100BTX)
			data |= PHY_AUTO_NEG_100BTX;
		if (link & PORT_REMOTE_10BT_FD)
			data |= PHY_AUTO_NEG_10BT_FD;
		if (link & PORT_REMOTE_10BT)
			data |= PHY_AUTO_NEG_10BT;
		if (data & ~PHY_AUTO_NEG_802_3)
			data |= PHY_REMOTE_ACKNOWLEDGE_NOT;
		break;
	default:
		processed = false;
		break;
	}
	if (processed)
		*val = data;
}

static void ksz8_w_phy(struct ksz_device *dev, u16 phy, u16 reg, u16 val)
{
	u8 p = phy;
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	u8 restart, speed, ctrl, data;

	switch (reg) {
	case PHY_REG_CTRL:

		/* Do not support PHY reset function. */
		if (val & PHY_RESET)
			break;
		ksz_pread8(dev, p, regs->p_speed_status, &speed);
		data = speed;
		if (val & PHY_HP_MDIX)
			data |= PORT_HP_MDIX;
		else
			data &= ~PORT_HP_MDIX;
		if (data != speed)
			ksz_pwrite8(dev, p, regs->p_speed_status, data);
		ksz_pread8(dev, p, regs->p_force_ctrl, &ctrl);
		data = ctrl;
		if (ksz_is_87(dev)) {
			if (!(val & PHY_AUTO_NEG_ENABLE))
				data |= PORT_AUTO_NEG_DISABLE;
			else
				data &= ~PORT_AUTO_NEG_DISABLE;

			/* Fiber port does not support auto-negotiation. */
			if (dev->ports[p].fiber)
				data |= PORT_AUTO_NEG_DISABLE;
		} else {
			if ((val & PHY_AUTO_NEG_ENABLE))
				data |= PORT_AUTO_NEG_ENABLE;
			else
				data &= ~PORT_AUTO_NEG_ENABLE;
		}
		if (val & PHY_SPEED_100MBIT)
			data |= PORT_FORCE_100_MBIT;
		else
			data &= ~PORT_FORCE_100_MBIT;
		if (val & PHY_FULL_DUPLEX)
			data |= PORT_FORCE_FULL_DUPLEX;
		else
			data &= ~PORT_FORCE_FULL_DUPLEX;
		if (data != ctrl)
			ksz_pwrite8(dev, p, regs->p_force_ctrl, data);
		ksz_pread8(dev, p, regs->p_neg_restart_ctrl, &restart);
		data = restart;
		if (val & PHY_LED_DISABLE)
			data |= PORT_LED_OFF;
		else
			data &= ~PORT_LED_OFF;
		if (val & PHY_TRANSMIT_DISABLE)
			data |= PORT_TX_DISABLE;
		else
			data &= ~PORT_TX_DISABLE;
		if (val & PHY_AUTO_NEG_RESTART)
			data |= PORT_AUTO_NEG_RESTART;
		else
			data &= ~(PORT_AUTO_NEG_RESTART);
		if (val & PHY_POWER_DOWN)
			data |= PORT_POWER_DOWN;
		else
			data &= ~PORT_POWER_DOWN;
		if (val & PHY_AUTO_MDIX_DISABLE)
			data |= PORT_AUTO_MDIX_DISABLE;
		else
			data &= ~PORT_AUTO_MDIX_DISABLE;
		if (val & PHY_FORCE_MDIX)
			data |= PORT_FORCE_MDIX;
		else
			data &= ~PORT_FORCE_MDIX;
		if (val & PHY_LOOPBACK)
			data |= PORT_PHY_LOOPBACK;
		else
			data &= ~PORT_PHY_LOOPBACK;
		if (data != restart)
			ksz_pwrite8(dev, p, regs->p_neg_restart_ctrl, data);
		break;
	case PHY_REG_AUTO_NEGOTIATION:
		ksz_pread8(dev, p, regs->p_local_ctrl, &ctrl);
		data = ctrl;
		data &= ~(PORT_AUTO_NEG_SYM_PAUSE |
			  PORT_AUTO_NEG_100BTX_FD |
			  PORT_AUTO_NEG_100BTX |
			  PORT_AUTO_NEG_10BT_FD |
			  PORT_AUTO_NEG_10BT);
		if (val & PHY_AUTO_NEG_SYM_PAUSE)
			data |= PORT_AUTO_NEG_SYM_PAUSE;
		if (val & PHY_AUTO_NEG_100BTX_FD)
			data |= PORT_AUTO_NEG_100BTX_FD;
		if (val & PHY_AUTO_NEG_100BTX)
			data |= PORT_AUTO_NEG_100BTX;
		if (val & PHY_AUTO_NEG_10BT_FD)
			data |= PORT_AUTO_NEG_10BT_FD;
		if (val & PHY_AUTO_NEG_10BT)
			data |= PORT_AUTO_NEG_10BT;
		if (data != ctrl)
			ksz_pwrite8(dev, p, regs->p_local_ctrl, data);
		break;
	default:
		break;
	}
}

static enum dsa_tag_protocol ksz8_get_tag_protocol(struct dsa_switch *ds,
						   int port)
{
	struct ksz_device *dev = ds->priv;

	return ksz_is_87(dev) ?
		DSA_TAG_PROTO_KSZ8795 : DSA_TAG_PROTO_KSZ8863;
}

static void ksz8_get_strings(struct dsa_switch *ds, int port,
			     u32 stringset, uint8_t *buf)
{
	struct ksz_device *dev = ds->priv;
	int switch_counter;
	int i;

	if (ksz_is_87(dev))
		switch_counter = TOTAL_KSZ8795_COUNTER_NUM;
	else
		switch_counter = TOTAL_KSZ8863_COUNTER_NUM;

	for (i = 0; i < switch_counter; i++) {
		const char *s;

		if (ksz_is_87(dev))
			s = ksz87xx_mib_names[i].string;
		else
			s = ksz88xx_mib_names[i].string;

		memcpy(buf + i * ETH_GSTRING_LEN, s, ETH_GSTRING_LEN);
	}
}

static void ksz8_cfg_port_member(struct ksz_device *dev, int port, u8 member)
{
	int membership = PORT_VLAN_MEMBERSHIP;
	u8 data;

	if (!ksz_is_87(dev))
		membership = (membership >> 2);

	ksz_pread8(dev, port, P_MIRROR_CTRL, &data);
	data &= ~(membership);
	data |= (member & dev->port_mask);
	ksz_pwrite8(dev, port, P_MIRROR_CTRL, data);
	dev->ports[port].member = member;
}

static void ksz8_port_stp_state_set(struct dsa_switch *ds, int port, u8 state)
{
	struct ksz_device *dev = ds->priv;
	int forward = dev->member;
	struct ksz_port *p;
	int member = -1;
	u8 data;

	p = &dev->ports[port];

	ksz_pread8(dev, port, P_STP_CTRL, &data);
	data &= ~(PORT_TX_ENABLE | PORT_RX_ENABLE | PORT_LEARN_DISABLE);

	switch (state) {
	case BR_STATE_DISABLED:
		data |= PORT_LEARN_DISABLE;
		if (port < dev->port_cnt)
			member = 0;
		break;
	case BR_STATE_LISTENING:
		data |= (PORT_RX_ENABLE | PORT_LEARN_DISABLE);
		if (port < dev->port_cnt &&
		    p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	case BR_STATE_LEARNING:
		data |= PORT_RX_ENABLE;
		break;
	case BR_STATE_FORWARDING:
		data |= (PORT_TX_ENABLE | PORT_RX_ENABLE);

		/* This function is also used internally. */
		if (port == dev->cpu_port)
			break;

		/* Port is a member of a bridge. */
		if (dev->br_member & BIT(port)) {
			dev->member |= BIT(port);
			member = dev->member;
		} else {
			member = dev->host_mask | p->vid_member;
		}
		break;
	case BR_STATE_BLOCKING:
		data |= PORT_LEARN_DISABLE;
		if (port < dev->port_cnt &&
		    p->stp_state == BR_STATE_DISABLED)
			member = dev->host_mask | p->vid_member;
		break;
	default:
		dev_err(ds->dev, "invalid STP state: %d\n", state);
		return;
	}

	ksz_pwrite8(dev, port, P_STP_CTRL, data);
	p->stp_state = state;
	if (data & PORT_RX_ENABLE)
		dev->rx_ports |= BIT(port);
	else
		dev->rx_ports &= ~BIT(port);
	if (data & PORT_TX_ENABLE)
		dev->tx_ports |= BIT(port);
	else
		dev->tx_ports &= ~BIT(port);

	/* Port membership may share register with STP state. */
	if (member >= 0 && member != p->member)
		ksz8_cfg_port_member(dev, port, (u8)member);

	/* Check if forwarding needs to be updated. */
	if (state != BR_STATE_FORWARDING) {
		if (dev->br_member & BIT(port))
			dev->member &= ~BIT(port);
	}

	/* When topology has changed the function ksz_update_port_member
	 * should be called to modify port forwarding behavior.
	 */
	if (forward != dev->member)
		ksz_update_port_member(dev, port);
}

static void ksz8_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	u8 *learn = kzalloc(dev->mib_port_cnt, GFP_KERNEL);
	int first, index, cnt;
	struct ksz_port *p;

	if ((uint)port < dev->mib_port_cnt) {
		first = port;
		cnt = port + 1;
	} else {
		/* Flush all ports. */
		first = 0;
		cnt = dev->mib_port_cnt;
	}
	for (index = first; index < cnt; index++) {
		p = &dev->ports[index];
		if (!p->on)
			continue;
		ksz_pread8(dev, index, P_STP_CTRL, &learn[index]);
		if (!(learn[index] & PORT_LEARN_DISABLE))
			ksz_pwrite8(dev, index, P_STP_CTRL,
				    learn[index] | PORT_LEARN_DISABLE);
	}
	ksz_cfg(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_DYN_MAC_TABLE, true);
	for (index = first; index < cnt; index++) {
		p = &dev->ports[index];
		if (!p->on)
			continue;
		if (!(learn[index] & PORT_LEARN_DISABLE))
			ksz_pwrite8(dev, index, P_STP_CTRL, learn[index]);
	}
	kfree(learn);
}

static int ksz8_port_vlan_filtering(struct dsa_switch *ds, int port, bool flag)
{
	struct ksz_device *dev = ds->priv;

	ksz_cfg(dev, S_MIRROR_CTRL, SW_VLAN_ENABLE, flag);

	return 0;
}

static void ksz8_port_vlan_add(struct dsa_switch *ds, int port,
			       const struct switchdev_obj_port_vlan *vlan)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	u16 vid, new_pvid = 0;
	u32 data = 0;
	u8 fid, member, valid;

	ksz_port_cfg(dev, port, P_TAG_CTRL, PORT_REMOVE_TAG, untagged);

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		ksz8_r_vlan_table(dev, vid, &data);
		ksz8_from_vlan(dev, data, &fid, &member, &valid);

		/* First time to setup the VLAN entry. */
		if (!valid) {
			/* Need to find a way to map VID to FID. */
			fid = 1;
			valid = 1;
		}
		member |= BIT(port);

		ksz8_to_vlan(dev, fid, member, valid, &data);
		ksz8_w_vlan_table(dev, vid, data);
		/* change PVID */
		if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
			new_pvid = vid;
	}

	if (new_pvid) {
		ksz_pread16(dev, port, REG_PORT_CTRL_VID, &vid);
		vid &= 0xfff;
		vid |= new_pvid;
		ksz_pwrite16(dev, port, REG_PORT_CTRL_VID, vid);
	}
}

static int ksz8_port_vlan_del(struct dsa_switch *ds, int port,
			      const struct switchdev_obj_port_vlan *vlan)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	struct ksz_device *dev = ds->priv;
	u32 data = 0;
	u16 vid, pvid, new_pvid = 0;
	u8 fid, member, valid;

	ksz_pread16(dev, port, REG_PORT_CTRL_VID, &pvid);
	pvid = pvid & 0xFFF;

	ksz_port_cfg(dev, port, P_TAG_CTRL, PORT_REMOVE_TAG, untagged);

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		ksz8_r_vlan_table(dev, vid, &data);
		ksz8_from_vlan(dev, data, &fid, &member, &valid);

		member &= ~BIT(port);

		/* Invalidate the entry if no more member. */
		if (!member) {
			fid = 0;
			valid = 0;
		}

		if (pvid == vid)
			new_pvid = 1;

		ksz8_to_vlan(dev, fid, member, valid, &data);
		ksz8_w_vlan_table(dev, vid, data);
	}

	if (new_pvid != pvid)
		ksz_pwrite16(dev, port, REG_PORT_CTRL_VID, pvid);

	return 0;
}

static int ksz8_port_mirror_add(struct dsa_switch *ds, int port,
				struct dsa_mall_mirror_tc_entry *mirror,
				bool ingress)
{
	struct ksz_device *dev = ds->priv;

	if (ingress) {
		ksz_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, true);
		dev->mirror_rx |= BIT(port);
	} else {
		ksz_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, true);
		dev->mirror_tx |= BIT(port);
	}

	ksz_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_SNIFFER, false);

	/* configure mirror port */
	if (dev->mirror_rx || dev->mirror_tx)
		ksz_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
			     PORT_MIRROR_SNIFFER, true);

	return 0;
}

static void ksz8_port_mirror_del(struct dsa_switch *ds, int port,
				 struct dsa_mall_mirror_tc_entry *mirror)
{
	struct ksz_device *dev = ds->priv;
	u8 data;

	if (mirror->ingress) {
		ksz_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, false);
		dev->mirror_rx &= ~BIT(port);
	} else {
		ksz_port_cfg(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, false);
		dev->mirror_tx &= ~BIT(port);
	}

	ksz_pread8(dev, port, P_MIRROR_CTRL, &data);

	if (!dev->mirror_rx && !dev->mirror_tx)
		ksz_port_cfg(dev, mirror->to_local_port, P_MIRROR_CTRL,
			     PORT_MIRROR_SNIFFER, false);
}

static void ksz8795_cpu_interface_select(struct ksz_device *dev, int port)
{
	struct ksz_port *p = &dev->ports[port];
	u8 data8;

	/* Configure MII interface for proper network communication. */
	ksz_read8(dev, REG_PORT_5_CTRL_6, &data8);
	data8 &= ~PORT_INTERFACE_TYPE;
	data8 &= ~PORT_GMII_1GPS_MODE;
	switch (dev->interface) {
	case PHY_INTERFACE_MODE_MII:
		p->phydev.speed = SPEED_100;
		break;
	case PHY_INTERFACE_MODE_RMII:
		data8 |= PORT_INTERFACE_RMII;
		p->phydev.speed = SPEED_100;
		break;
	case PHY_INTERFACE_MODE_GMII:
		data8 |= PORT_GMII_1GPS_MODE;
		data8 |= PORT_INTERFACE_GMII;
		p->phydev.speed = SPEED_1000;
		break;
	default:
		data8 &= ~PORT_RGMII_ID_IN_ENABLE;
		data8 &= ~PORT_RGMII_ID_OUT_ENABLE;
		if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
		    dev->interface == PHY_INTERFACE_MODE_RGMII_RXID)
			data8 |= PORT_RGMII_ID_IN_ENABLE;
		if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
		    dev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
			data8 |= PORT_RGMII_ID_OUT_ENABLE;
		data8 |= PORT_GMII_1GPS_MODE;
		data8 |= PORT_INTERFACE_RGMII;
		p->phydev.speed = SPEED_1000;
		break;
	}
	ksz_write8(dev, REG_PORT_5_CTRL_6, data8);
	p->phydev.duplex = 1;
}

static void ksz8_port_setup(struct ksz_device *dev, int port, bool cpu_port)
{
	struct ksz_port *p = &dev->ports[port];
	u8 member;
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_masks *masks = ksz8->masks;

	/* enable broadcast storm limit */
	ksz_port_cfg(dev, port, P_BCAST_STORM_CTRL, PORT_BROADCAST_STORM, true);

	if (ksz_is_87(dev))
		ksz8795_set_prio_queue(dev, port, 4);

	/* disable DiffServ priority */
	ksz_port_cfg(dev, port, P_PRIO_CTRL, PORT_DIFFSERV_ENABLE, false);

	/* replace priority */
	ksz_port_cfg(dev, port, P_802_1P_CTRL,
		     masks->port_802_1p_remapping, false);

	/* enable 802.1p priority */
	ksz_port_cfg(dev, port, P_PRIO_CTRL, PORT_802_1P_ENABLE, true);

	if (cpu_port) {
		if (ksz_is_87(dev))
			ksz8795_cpu_interface_select(dev, port);

		member = dev->port_mask;
		dev->on_ports = dev->host_mask;
		dev->live_ports = dev->host_mask;
	} else {
		member = dev->host_mask | p->vid_member;
		dev->on_ports |= BIT(port);

		/* Link was detected before port is enabled. */
		if (p->phydev.link)
			dev->live_ports |= BIT(port);
	}
	ksz8_cfg_port_member(dev, port, member);
}

static void ksz8_config_cpu_port(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct ksz8 *ksz8 = dev->priv;
	struct ksz_regs *regs = ksz8->regs;
	struct ksz_masks *masks = ksz8->masks;
	struct ksz_port *p;
	u8 remote;
	int i;

	ds->num_ports = dev->port_cnt + 1;

	/* Switch marks the maximum frame with extra byte as oversize. */
	ksz_cfg(dev, REG_SW_CTRL_2, SW_LEGAL_PACKET_DISABLE, true);
	ksz_cfg(dev, regs->s_tail_tag_ctrl, masks->sw_tail_tag_enable, true);

	p = &dev->ports[dev->cpu_port];
	p->vid_member = dev->port_mask;
	p->on = 1;

	ksz8_port_setup(dev, dev->cpu_port, true);
	dev->member = dev->host_mask;

	for (i = 0; i < dev->port_cnt; i++) {
		p = &dev->ports[i];

		/* Initialize to non-zero so that ksz_cfg_port_member() will
		 * be called.
		 */
		p->vid_member = BIT(i);
		p->member = dev->port_mask;
		ksz8_port_stp_state_set(ds, i, BR_STATE_DISABLED);

		/* Last port may be disabled. */
		if (i == dev->port_cnt)
			break;
		p->on = 1;
		p->phy = 1;
	}
	for (i = 0; i < dev->phy_port_cnt; i++) {
		p = &dev->ports[i];
		if (!p->on)
			continue;
		if (ksz_is_87(dev)) {
			ksz_pread8(dev, i, regs->p_remote_status, &remote);
			if (remote & PORT_FIBER_MODE)
				p->fiber = 1;
		}
		if (p->fiber)
			ksz_port_cfg(dev, i, P_STP_CTRL, PORT_FORCE_FLOW_CTRL,
				     true);
		else
			ksz_port_cfg(dev, i, P_STP_CTRL, PORT_FORCE_FLOW_CTRL,
				     false);
	}
}

static int ksz8_setup(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct alu_struct alu;
	int i, ret = 0;

	dev->vlan_cache = devm_kcalloc(dev->dev, sizeof(struct vlan_table),
				       dev->num_vlans, GFP_KERNEL);
	if (!dev->vlan_cache)
		return -ENOMEM;

	ksz8_reset_switch(dev);
	if (ret) {
		dev_err(ds->dev, "failed to reset switch\n");
		return ret;
	}

	if (ksz_is_88(dev)) {
		ksz_cfg(dev, KSZ8863_REG_HOST_MODE, KSZ8863_INTERNAL_RMII_CLK,
			dev->internal_rmii_clk);

		if (dev->drive_strength)
			ksz_cfg(dev, KSZ8863_REG_GLOBAL_CTRL_12,
				KSZ8863_DRIVE_STRENGTH,
				dev->drive_strength == 16);
	}

	ksz_cfg(dev, S_REPLACE_VID_CTRL, SW_FLOW_CTRL, true);

	/* Enable automatic fast aging when link changed detected. */
	ksz_cfg(dev, S_LINK_AGING_CTRL, SW_LINK_AUTO_AGING, true);

	/* Enable aggressive back off algorithm in half duplex mode. */
	regmap_update_bits(dev->regmap[0], REG_SW_CTRL_1,
			   SW_AGGR_BACKOFF, SW_AGGR_BACKOFF);

	/*
	 * Make sure unicast VLAN boundary is set as default and
	 * enable no excessive collision drop.
	 */
	regmap_update_bits(dev->regmap[0], REG_SW_CTRL_2,
			   UNICAST_VLAN_BOUNDARY | NO_EXC_COLLISION_DROP,
			   UNICAST_VLAN_BOUNDARY | NO_EXC_COLLISION_DROP);

	ksz8_config_cpu_port(ds);

	ksz_cfg(dev, REG_SW_CTRL_2, MULTICAST_STORM_DISABLE, true);

	ksz_cfg(dev, S_REPLACE_VID_CTRL, SW_REPLACE_VID, false);

	ksz_cfg(dev, S_MIRROR_CTRL, SW_MIRROR_RX_TX, false);

	/* set broadcast storm protection 10% rate */
	regmap_update_bits(dev->regmap[1], S_REPLACE_VID_CTRL,
			   BROADCAST_STORM_RATE,
			   (BROADCAST_STORM_VALUE *
			   BROADCAST_STORM_PROT_RATE) / 100);

	for (i = 0; i < (dev->num_vlans / 2); i++)
		ksz8_r_vlan_entries(dev, i);

	/* Setup STP address for STP operation. */
	memset(&alu, 0, sizeof(alu));
	ether_addr_copy(alu.mac, eth_stp_addr);
	alu.is_static = true;
	alu.is_override = true;
	alu.port_forward = dev->host_mask;

	ksz8_w_sta_mac_table(dev, 0, &alu);

	ksz_init_mib_timer(dev);

	return 0;
}

static const struct dsa_switch_ops ksz8_switch_ops = {
	.get_tag_protocol	= ksz8_get_tag_protocol,
	.setup			= ksz8_setup,
	.phy_read		= ksz_phy_read16,
	.phy_write		= ksz_phy_write16,
	.adjust_link		= ksz_adjust_link,
	.port_enable		= ksz_enable_port,
	.port_disable		= ksz_disable_port,
	.get_strings		= ksz8_get_strings,
	.get_ethtool_stats	= ksz_get_ethtool_stats,
	.get_sset_count		= ksz_sset_count,
	.port_bridge_join	= ksz_port_bridge_join,
	.port_bridge_leave	= ksz_port_bridge_leave,
	.port_stp_state_set	= ksz8_port_stp_state_set,
	.port_fast_age		= ksz_port_fast_age,
	.port_vlan_filtering	= ksz8_port_vlan_filtering,
	.port_vlan_prepare	= ksz_port_vlan_prepare,
	.port_vlan_add		= ksz8_port_vlan_add,
	.port_vlan_del		= ksz8_port_vlan_del,
	.port_fdb_dump		= ksz_port_fdb_dump,
	.port_mdb_prepare       = ksz_port_mdb_prepare,
	.port_mdb_add           = ksz_port_mdb_add,
	.port_mdb_del           = ksz_port_mdb_del,
	.port_mirror_add	= ksz8_port_mirror_add,
	.port_mirror_del	= ksz8_port_mirror_del,
};

static u32 ksz8_get_port_addr(int port, int offset)
{
	return PORT_CTRL_ADDR(port, offset);
}

static int ksz8_switch_detect(struct ksz_device *dev)
{
	u8 id1, id2;
	u16 id16;
	int ret;

	/* read chip id */
	ret = ksz_read16(dev, REG_CHIP_ID0, &id16);
	if (ret)
		return ret;

	id1 = id16 >> 8;
	id2 = id16 & SW_CHIP_ID_M;

	switch (id1) {
	case KSZ87_FAMILY_ID:
		if ((id2 != CHIP_ID_94 && id2 != CHIP_ID_95))
			return -ENODEV;

		dev->mib_port_cnt = KSZ8795_TOTAL_PORT_NUM;
		dev->phy_port_cnt = KSZ8795_SWITCH_PORT_NUM;
		dev->port_cnt = KSZ8795_SWITCH_PORT_NUM;
		if (id2 == CHIP_ID_95) {
			u8 val;

			id2 = 0x95;
			ksz_read8(dev, KSZ8795_REG_PORT_STATUS_0, &val);
			if (val & PORT_FIBER_MODE)
				id2 = 0x65;
		} else if (id2 == CHIP_ID_94) {
			dev->port_cnt--;
			dev->last_port = dev->port_cnt;
			id2 = 0x94;
		}
		break;
	case KSZ88_FAMILY_ID:
		if (id2 != CHIP_ID_63)
			return -ENODEV;

		dev->mib_port_cnt = KSZ8863_TOTAL_PORT_NUM;
		dev->phy_port_cnt = KSZ8863_SWITCH_PORT_NUM;
		dev->port_cnt = KSZ8863_SWITCH_PORT_NUM;
		break;
	default:
		dev_err(dev->dev, "invalid family id: %d\n", id1);
		return -ENODEV;
	}
	id16 &= ~0xff;
	id16 |= id2;
	dev->chip_id = id16;

	dev->cpu_port = dev->mib_port_cnt - 1;
	dev->host_mask = BIT(dev->cpu_port);

	return 0;
}

struct ksz_chip_data {
	u16 chip_id;
	const char *dev_name;
	int num_vlans;
	int num_alus;
	int num_statics;
	int cpu_ports;
	int port_cnt;
};

static const struct ksz_chip_data ksz8_switch_chips[] = {
	{
		.chip_id = 0x8795,
		.dev_name = "KSZ8795",
		.num_vlans = 4096,
		.num_alus = 0,
		.num_statics = 8,
		.cpu_ports = 0x10,	/* can be configured as cpu port */
		.port_cnt = 4,		/* total physical port count */
	},
	{
		.chip_id = 0x8794,
		.dev_name = "KSZ8794",
		.num_vlans = 4096,
		.num_alus = 0,
		.num_statics = 8,
		.cpu_ports = 0x10,	/* can be configured as cpu port */
		.port_cnt = 3,		/* total physical port count */
	},
	{
		.chip_id = 0x8765,
		.dev_name = "KSZ8765",
		.num_vlans = 4096,
		.num_alus = 0,
		.num_statics = 8,
		.cpu_ports = 0x10,	/* can be configured as cpu port */
		.port_cnt = 4,		/* total physical port count */
	},
	{
		.chip_id = 0x8830,
		.dev_name = "KSZ8863/KSZ8873",
		.num_vlans = 16,
		.num_alus = 0,
		.num_statics = 8,
		.cpu_ports = 0x4,	/* can be configured as cpu port */
		.port_cnt = 2,		/* total physical port count */
	},
};

static int ksz8_switch_init(struct ksz_device *dev)
{
	int i;
	struct ksz8 *ksz8 = dev->priv;

	dev->ds->ops = &ksz8_switch_ops;

	for (i = 0; i < ARRAY_SIZE(ksz8_switch_chips); i++) {
		const struct ksz_chip_data *chip = &ksz8_switch_chips[i];

		if (dev->chip_id == chip->chip_id) {
			dev->name = chip->dev_name;
			dev->num_vlans = chip->num_vlans;
			dev->num_alus = chip->num_alus;
			dev->num_statics = chip->num_statics;
			dev->port_cnt = chip->port_cnt;
			dev->cpu_ports = chip->cpu_ports;

			break;
		}
	}

	/* no switch found */
	if (!dev->cpu_ports)
		return -ENODEV;

	if (ksz_is_87(dev)) {
		ksz8->regs = &ksz8795_regs;
		ksz8->masks = &ksz8795_masks;
		ksz8->shifts = &ksz8795_shifts;
		dev->mib_cnt = TOTAL_KSZ8795_COUNTER_NUM;
	} else {
		ksz8->regs = &ksz8863_regs;
		ksz8->masks = &ksz8863_masks;
		ksz8->shifts = &ksz8863_shifts;
		dev->mib_cnt = TOTAL_KSZ8863_COUNTER_NUM;

		if (dev->dev->of_node) {
			dev->internal_rmii_clk =
				of_property_read_bool(dev->dev->of_node,
						      "microchip,internal-rmii-clk");

			if (!of_property_read_u32(dev->dev->of_node,
						  "microchip,drive-strength",
						  &dev->drive_strength)) {
				switch (dev->drive_strength) {
				case 8:
				case 16:
					break;

				default:
					dev_err(dev->dev,
						"invalid drive strength %d\n",
						dev->drive_strength);
					return -EINVAL;
				}
			}
		}
	}

	dev->port_mask = BIT(dev->port_cnt) - 1;
	dev->port_mask |= dev->host_mask;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;

	i = dev->mib_port_cnt;
	dev->ports = devm_kzalloc(dev->dev, sizeof(struct ksz_port) * i,
				  GFP_KERNEL);
	if (!dev->ports)
		return -ENOMEM;
	for (i = 0; i < dev->mib_port_cnt; i++) {
		mutex_init(&dev->ports[i].mib.cnt_mutex);
		dev->ports[i].mib.counters =
			devm_kzalloc(dev->dev,
				     sizeof(u64) *
				     (dev->mib_cnt + 1),
				     GFP_KERNEL);
		if (!dev->ports[i].mib.counters)
			return -ENOMEM;
	}

	/* set the real number of ports */
	dev->ds->num_ports = dev->port_cnt + 1;

	return 0;
}

static void ksz8_switch_exit(struct ksz_device *dev)
{
	ksz8_reset_switch(dev);
}

static const struct ksz_dev_ops ksz8_dev_ops = {
	.get_port_addr = ksz8_get_port_addr,
	.cfg_port_member = ksz8_cfg_port_member,
	.flush_dyn_mac_table = ksz8_flush_dyn_mac_table,
	.port_setup = ksz8_port_setup,
	.r_phy = ksz8_r_phy,
	.w_phy = ksz8_w_phy,
	.r_dyn_mac_table = ksz8_r_dyn_mac_table,
	.r_sta_mac_table = ksz8_r_sta_mac_table,
	.w_sta_mac_table = ksz8_w_sta_mac_table,
	.r_mib_cnt = ksz8_r_mib_cnt,
	.r_mib_pkt = ksz8_r_mib_pkt,
	.freeze_mib = ksz8_freeze_mib,
	.port_init_cnt = ksz8_port_init_cnt,
	.shutdown = ksz8_reset_switch,
	.detect = ksz8_switch_detect,
	.init = ksz8_switch_init,
	.exit = ksz8_switch_exit,
};

int ksz8_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &ksz8_dev_ops);
}
EXPORT_SYMBOL(ksz8_switch_register);

MODULE_AUTHOR("Tristram Ha <Tristram.Ha@microchip.com>");
MODULE_DESCRIPTION("Microchip KSZ8795 Series Switch DSA Driver");
MODULE_LICENSE("GPL");
