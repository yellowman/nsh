/* request types for bridge_cfg() */

#define PRIORITY	0
#define	HELLOTIME	1
#define FWDDELAY	2
#define MAXAGE		3
#define MAXADDR		4
#define TIMEOUT		5

#define DEFAULT_PRIORITY	32768
#define DEFAULT_HELLOTIME	2
#define DEFAULT_FWDDELAY	15
#define DEFAULT_MAXAGE		15
#define DEFAULT_MAXADDR		100
#define DEFAULT_TIMEOUT		240
#define DEFAULT_IFPRIORITY	128

/* request types for bridge_list() */

#define NOLEARNING 	1
#define NODISCOVER	2
#define BLOCKNONIP	3
#define STP		4
#define SPAN		11
#define CONF_IFPRIORITY	100
#define SHOW_STPSTATE	101
#define MEMBER		102

/* blah */

#define IFBAFBITS	"\1STATIC"
#define IFBIFBITS	"\1LEARNING\2DISCOVER\3BLOCKNONIP\4STP\11SPAN"
