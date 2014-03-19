#ifndef _LINUX_NETFILTER_XT_TARGET_RAWNAT
#define _LINUX_NETFILTER_XT_TARGET_RAWNAT 1

struct xt_rawnat_tginfo {
	union nf_inet_addr addr;
	__u8 mask;
	unsigned int match;
	unsigned int table;
};

enum {
        XT_TABCLAS_MATCH = 1 << 0,
        XT_TABCLAS_TABLE = 1 << 1,
};


#define SO_RAWNAT_BASE_CTL 80

#define IPT_SO_SET_RAWNAT_IP (SO_RAWNAT_BASE_CTL + 1)
#define IPT_SO_SET_RAWNAT_FREE_IP (SO_RAWNAT_BASE_CTL + 2)
#define IPT_SO_SET_RAWNAT_MAX		 IPT_SO_SET_RAWNAT_FREE_IP

#define IPT_SO_GET_RAWNAT_PREPARE_READ (SO_RAWNAT_BASE_CTL + 4)
#define IPT_SO_GET_RAWNAT_PREPARE_READ_FLUSH (SO_RAWNAT_BASE_CTL + 5)
#define IPT_SO_GET_RAWNAT_GET_DATA (SO_RAWNAT_BASE_CTL + 6)
#define IPT_SO_GET_RAWNAT_GET_HANDLE_USAGE (SO_RAWNAT_BASE_CTL + 7)
#define IPT_SO_GET_RAWNAT_GET_TABLE_NAMES (SO_RAWNAT_BASE_CTL + 8)
#define IPT_SO_GET_RAWNAT_MAX	  IPT_SO_GET_RAWNAT_GET_TABLE_NAMES


struct ipt_rnat_handle_sockopt {
	uint32_t tab_num;				   /* Used for HANDLE_FREE */
	__be32 ip;
	__be32 repl_ip;
};


#endif /* _LINUX_NETFILTER_XT_TARGET_RAWNAT */
