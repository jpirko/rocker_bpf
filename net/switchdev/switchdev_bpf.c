/*
 * net/switchdev/switchdev_bpf.c - Switch device API - BPF part
 * Copyright (c) 2015 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <net/switchdev.h>

static enum bpf_func_id __get_func_id(const struct bpf_verifier_ops *ops,
				      __s32 imm_func)
{
	const struct bpf_func_proto *fn;
	int i;

	for (i = 0; i < __BPF_FUNC_MAX_ID; i++) {
		fn = ops->get_func_proto(imm_func);
		if (fn && fn->func == imm_func + __bpf_call_base)
			return i;
	}
	BUG();
}

static int __prog_check_convert(const struct bpf_verifier_ops *ops,
				struct bpf_insn *dst,
				const struct bpf_insn *src, u32 len)
{
	int i;

	for (i = 0; i < len; i++) {
		memcpy(dst, src, sizeof(*dst));
		if (src->code == (BPF_JMP | BPF_CALL))
			dst->imm = __get_func_id(ops, src->imm);
		if (src->code == (BPF_JMP | BPF_CALL | BPF_X))
			return -EOPNOTSUPP; /* We do not support tail call now */
		dst++;
		src++;
	}
	return 0;
}

static int switchdev_bpf_prog_obj_create(struct switchdev_obj *obj,
					 const struct bpf_prog *prog)
{
	struct bpf_insn *insnsi;
	int err;

	insnsi = kmalloc(sizeof(*insnsi) * prog->len, GFP_KERNEL);
	if (!insnsi)
		return -ENOMEM;

	err = __prog_check_convert(prog->aux->ops, insnsi,
				   prog->insnsi, prog->len);
	if (err)
		goto err_prog_check_convert;

	obj->id = SWITCHDEV_OBJ_PORT_BPF_PROG;
	obj->u.bpf_prog.insnsi = insnsi;
	obj->u.bpf_prog.len = prog->len;

	return 0;

err_prog_check_convert:
	kfree(insnsi);
	return err;
}

static void switchdev_bpf_prog_obj_destroy(struct switchdev_obj *obj)
{
	kfree(obj->u.bpf_prog.insnsi);
}

/**
 *	switchdev_port_bpf_prog_add - Add BPF program to port
 *
 *	@dev: port device
 *	@prog: BPF program structure
 *
 *	Add BPF program to switch device.
 */
int switchdev_port_bpf_prog_add(struct net_device *dev,
				const struct bpf_prog *prog)
{
	struct switchdev_obj obj;
	int err;

	err = switchdev_bpf_prog_obj_create(&obj, prog);
	if (err)
		return err;
	err = switchdev_port_obj_add(dev, &obj);
	switchdev_bpf_prog_obj_destroy(&obj);
	return err;

}
EXPORT_SYMBOL_GPL(switchdev_port_bpf_prog_add);

/**
 *	switchdev_port_bpf_prog_del - Del BPF program from port
 *
 *	@dev: port device
 *	@prog: BPF program structure
 *
 *	Delete BPF program from switch device.
 */
int switchdev_port_bpf_prog_del(struct net_device *dev,
				const struct bpf_prog *prog)
{
	struct switchdev_obj obj;
	int err;

	err = switchdev_bpf_prog_obj_create(&obj, prog);
	if (err)
		return err;
	err = switchdev_port_obj_del(dev, &obj);
	switchdev_bpf_prog_obj_destroy(&obj);
	return err;
}
EXPORT_SYMBOL_GPL(switchdev_port_bpf_prog_del);
