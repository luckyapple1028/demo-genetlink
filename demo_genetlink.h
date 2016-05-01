

#ifndef _DEMO_GENETLINK_KERN_H
#define _DEMO_GENETLINK_KERN_H


#define	DEMO_GENL_NAME		"DEMO_GEN_CTRL"
#define	DEMO_GENL_VERSION	0x1


/*
 * Commands sent from userspace
 * Not versioned. New commands should only be inserted at the enum's end
 * prior to __DEMO_CMD_MAX
 */

enum {
	DEMO_CMD_UNSPEC = 0,	/* Reserved */
	DEMO_CMD_ECHO,			/* user->kernel request/get-response */
	DEMO_CMD_REPLY,			/* kernel->user event */
	__DEMO_CMD_MAX,
};
#define DEMO_CMD_MAX (__DEMO_CMD_MAX - 1)


enum {
	DEMO_CMD_ATTR_UNSPEC = 0,
	DEMO_CMD_ATTR_MESG,		/* demo message  */
	DEMO_CMD_ATTR_DATA,		/* demo data */
	__DEMO_CMD_ATTR_MAX,
};
#define DEMO_CMD_ATTR_MAX (__DEMO_CMD_ATTR_MAX - 1)





#endif /* _DEMO_GENETLINK_KERN_H */

