#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <net/genetlink.h> 

#include "demo_genetlink.h"


static struct genl_family demo_family = {
	.id			= GENL_ID_GENERATE,
	.name		= DEMO_GENL_NAME,
	.version	= DEMO_GENL_VERSION,
	.maxattr	= DEMO_CMD_ATTR_MAX,
};

static const struct nla_policy demo_cmd_policy[DEMO_CMD_ATTR_MAX+1] = {
	[DEMO_CMD_ATTR_MESG]	= { .type = NLA_STRING },
	[DEMO_CMD_ATTR_DATA]	= { .type = NLA_S32 },	
};

static int demo_prepare_reply(struct genl_info *info, u8 cmd, struct sk_buff **skbp, size_t size)
{
	struct sk_buff *skb;
	void *reply;

	/*
	 * If new attributes are added, please revisit this allocation
	 */
	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	if (!info)
		return -EINVAL;

	/* 构建回发消息头 */	
	reply = genlmsg_put_reply(skb, info, &demo_family, 0, cmd);
	if (reply == NULL) {
		nlmsg_free(skb);
		return -EINVAL;
	}

	*skbp = skb;
	return 0;
}

static int demo_mk_reply(struct sk_buff *skb, int aggr, void *data, int len)  
{  
    /* add a netlink attribute to a socket buffer */  
    return nla_put(skb, aggr, len, data); 

	/* 
	 * nla是可以分level的(调用nla_nest_start和nla_nest_end进行)，
	 * 由于本示例程序attr较少，所以就不进行分层了，分层具体可见
	 * 内核中其他使用到genetlink的地方。
	 */
}  

static int demo_send_reply(struct sk_buff *skb, struct genl_info *info)
{
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(skb));
	void *reply = genlmsg_data(genlhdr);

	genlmsg_end(skb, reply);

	return genlmsg_reply(skb, info);
}

static int cmd_attr_echo_message(struct genl_info *info)
{
	struct nlattr *na; 
	char *msg;  
	struct sk_buff *rep_skb;
	size_t size;
	int ret;

	/* 读取用户下发的消息 */
	na = info->attrs[DEMO_CMD_ATTR_MESG];
	if (!na)
		return -EINVAL;

	msg = (char *)nla_data(na);
	pr_info("demo generic netlink receive echo mesg %s\n", msg);  

	/* 回发消息 */
	size = nla_total_size(strlen(msg)+1);
	
	/* 准备构建消息 */
	ret = demo_prepare_reply(info, DEMO_CMD_REPLY, &rep_skb, size);
	if (ret < 0)
		return ret;

	/* 填充消息 */
	ret = demo_mk_reply(rep_skb, DEMO_CMD_ATTR_MESG, msg, size); 
	if (ret < 0)
		goto err;

	/* 完成构建并发送 */
	return demo_send_reply(rep_skb, info);

err:
	nlmsg_free(rep_skb);
	return ret;	
}

static int cmd_attr_echo_data(struct genl_info *info)
{
	struct nlattr *na; 
	s32	data;
	struct sk_buff *rep_skb;
	size_t size;
	int ret;

	/* 读取用户下发的数据 */
	na = info->attrs[DEMO_CMD_ATTR_DATA];
	if (!na)
		return -EINVAL;

	data = nla_get_s32(info->attrs[DEMO_CMD_ATTR_DATA]);
	pr_info("demo generic netlink receive echo data %d\n", data);  

	/* 回发数据 */
	size = nla_total_size(sizeof(s32));

	ret = demo_prepare_reply(info, DEMO_CMD_REPLY, &rep_skb, size);
	if (ret < 0)
		return ret;

	/* 为了简单这里直接调用netlink库函数(对于需求的丰富可以自行封装) */
	ret = nla_put_s32(rep_skb, DEMO_CMD_ATTR_DATA, data);
	if (ret < 0)
		goto err;

	return demo_send_reply(rep_skb, info);

err:
	nlmsg_free(rep_skb);
	return ret; 
}

static int demo_echo_cmd(struct sk_buff *skb, struct genl_info *info)
{
	if (info->attrs[DEMO_CMD_ATTR_MESG])
		return cmd_attr_echo_message(info);
	else if (info->attrs[DEMO_CMD_ATTR_DATA])
		return cmd_attr_echo_data(info);
	else
		return -EINVAL;
}

static const struct genl_ops demo_ops[] = {
	{
		.cmd		= DEMO_CMD_ECHO,
		.doit		= demo_echo_cmd,
		.policy		= demo_cmd_policy,
		.flags		= GENL_ADMIN_PERM,
	},
};

static int __init demo_genetlink_init(void) 
{  
	int ret;  
	pr_info("demo generic netlink module %d init...\n", DEMO_GENL_VERSION);  
  
	ret = genl_register_family_with_ops(&demo_family, demo_ops);  
	if (ret != 0) {  
		pr_info("failed to init demo generic netlink example module\n");  
		return ret;
	}  

	pr_info("demo generic netlink module init success\n");  

	return 0; 
}  
  
static void __exit demo_genetlink_exit(void) 
{  
	int ret;  
	printk("demo generic netlink deinit.\n");  

	ret = genl_unregister_family(&demo_family);  
	if(ret != 0) {  
		printk("faled to unregister family:%i\n", ret);  
	}  
}  

module_init(demo_genetlink_init);  
module_exit(demo_genetlink_exit);  
MODULE_LICENSE("GPL");  

