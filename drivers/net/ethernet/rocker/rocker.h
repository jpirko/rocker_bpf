/*
 * drivers/net/ethernet/rocker/rocker.h - Rocker switch device driver
 * Copyright (c) 2014-2015 Jiri Pirko <jiri@resnulli.us>
 * Copyright (c) 2014-2015 Scott Feldman <sfeldma@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ROCKER_H
#define _ROCKER_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/neighbour.h>
#include <net/switchdev.h>

#include "rocker_hw.h"

struct rocker_desc_info {
	char *data; /* mapped */
	size_t data_size;
	size_t tlv_size;
	struct rocker_desc *desc;
	dma_addr_t mapaddr;
};

struct rocker;

unsigned int rocker_port_count_get(struct rocker *rocker);
struct rocker_port *rocker_port_get(struct rocker *rocker, int port_index);

struct rocker_port;

struct net_device *rocker_port_netdev_get(struct rocker_port *rocker_port);
void *rocker_port_world_priv_get(struct rocker_port *rocker_port);
u32 rocker_port_pport_get(struct rocker_port *rocker_port);

typedef int (*rocker_cmd_prep_cb_t)(const struct rocker_port *rocker_port,
				    struct rocker_desc_info *desc_info,
				    void *priv);

typedef int (*rocker_cmd_proc_cb_t)(const struct rocker_port *rocker_port,
				    const struct rocker_desc_info *desc_info,
				    void *priv);

int rocker_cmd_exec(struct rocker_port *rocker_port, bool nowait,
		    rocker_cmd_prep_cb_t prepare, void *prepare_priv,
		    rocker_cmd_proc_cb_t process, void *process_priv);

int rocker_port_set_learning(struct rocker_port *rocker_port,
			     bool learning);

struct rocker_world_ops {
	const char *kind;
	size_t priv_size;
	size_t port_priv_size;
	u8 mode;
	int (*init)(struct rocker *rocker, void *priv);
	void (*fini)(void *priv);
	int (*port_init)(struct rocker_port *rocker_port, void *priv,
			 void *port_priv);
	void (*port_fini)(void *port_priv);
	int (*port_open)(void *port_priv);
	void (*port_stop)(void *port_priv);
	int (*port_attr_stp_state_set)(void *port_priv, u8 state,
				       struct switchdev_trans *trans);
	int (*port_attr_bridge_flags_set)(void *port_priv,
					  unsigned long brport_flags,
					  struct switchdev_trans *trans);
	int (*port_attr_bridge_flags_get)(void *port_priv,
					  unsigned long *p_brport_flags);
	int (*port_obj_vlan_add)(void *port_priv,
				 const struct switchdev_obj_port_vlan *vlan,
				 struct switchdev_trans *trans);
	int (*port_obj_vlan_del)(void *port_priv,
				 const struct switchdev_obj_port_vlan *vlan);
	int (*port_obj_vlan_dump)(void *port_priv,
				  struct switchdev_obj_port_vlan *vlan,
				  switchdev_obj_dump_cb_t *cb);
	int (*port_obj_fib4_add)(void *port_priv,
				 const struct switchdev_obj_ipv4_fib *fib4,
				 struct switchdev_trans *trans);
	int (*port_obj_fib4_del)(void *port_priv,
				 const struct switchdev_obj_ipv4_fib *fib4);
	int (*port_obj_fdb_add)(void *port_priv,
				const struct switchdev_obj_port_fdb *fdb,
				struct switchdev_trans *trans);
	int (*port_obj_fdb_del)(void *port_priv,
				const struct switchdev_obj_port_fdb *fdb);
	int (*port_obj_fdb_dump)(void *port_priv,
				 struct switchdev_obj_port_fdb *fdb,
				 switchdev_obj_dump_cb_t *cb);
	int (*port_master_linked)(void *port_priv, struct net_device *master);
	int (*port_master_unlinked)(void *port_priv, struct net_device *master);
	int (*port_neigh_update)(void *port_priv, struct neighbour *n);
	int (*port_neigh_destroy)(void *port_priv, struct neighbour *n);
	int (*port_ev_mac_vlan_seen)(void *port_priv,
				     const unsigned char *addr,
				     __be16 vlan_id);
};

extern struct rocker_world_ops rocker_ofdpa_ops;

#endif
