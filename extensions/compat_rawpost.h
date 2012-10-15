#ifndef XTA_COMPAT_RAWPOST_H
#define XTA_COMPAT_RAWPOST_H 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
typedef struct sk_buff sk_buff_t;
#else
typedef struct sk_buff *sk_buff_t;
#endif

#endif /* XTA_COMPAT_RAWPOST_H */
