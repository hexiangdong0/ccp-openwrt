/********************************************************************/
/************************#include "tcp_ccp.h"************************/
/*******************************begin********************************/
#include <linux/net.h>
#include <linux/tcp.h>
/********************************************************************/
/**********************#include "libccp/ccp.h"***********************/
/*******************************begin********************************/
#ifdef __KERNEL__
    #include <linux/types.h>
    #include <linux/module.h>
#else
    #include <stdbool.h>
    #include <pthread.h> // for mutex
#endif

/********************************************************************/
/*************************#include "types.h"*************************/
/*******************************begin********************************/
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/********************************************************************/
/***********************#include "ccp_error.h"***********************/
/*******************************begin********************************/
#define LIBCCP_OK 0

// Function parameter checking
#define LIBCCP_MISSING_ARG -11
#define LIBCCP_NULL_ARG -12

// Buffer size checking
#define LIBCCP_BUFSIZE_NEGATIVE -21
#define LIBCCP_BUFSIZE_TOO_SMALL -22
#define LIBCCP_MSG_TOO_LONG -23

// Se/deserializing messages
#define LIBCCP_WRITE_INVALID_HEADER_TYPE -31
#define LIBCCP_READ_INVALID_HEADER_TYPE -32
#define LIBCCP_READ_INVALID_OP -33
#define LIBCCP_READ_REG_NOT_ALLOWED -34
#define LIBCCP_READ_INVALID_RETURN_REG -35
#define LIBCCP_READ_INVALID_LEFT_REG -36
#define LIBCCP_READ_INVALID_RIGHT_REG -37

// Install message parse errors
#define LIBCCP_INSTALL_TYPE_MISMATCH -41
#define LIBCCP_INSTALL_TOO_MANY_EXPR -42
#define LIBCCP_INSTALL_TOO_MANY_INSTR -43

// Update message parse errors
#define LIBCCP_UPDATE_TYPE_MISMATCH -51
#define LIBCCP_UPDATE_TOO_MANY -52
#define LIBCCP_UPDATE_INVALID_REG_TYPE -53

// Change message parse errors
#define LIBCCP_CHANGE_TYPE_MISMATCH -61
#define LIBCCP_CHANGE_TOO_MANY -62

// Connection object
#define LIBCCP_UNKNOWN_CONNECTION -71
#define LIBCCP_CREATE_PENDING -72
#define LIBCCP_CONNECTION_NOT_INITIALIZED -73

// Datapath programs
#define LIBCCP_PROG_TABLE_FULL -81
#define LIBCCP_PROG_NOT_FOUND -82

// VM instruction execution errors
#define LIBCCP_ADD_INT_OVERFLOW -91
#define LIBCCP_DIV_BY_ZERO -92
#define LIBCCP_MUL_INT_OVERFLOW -93
#define LIBCCP_SUB_INT_UNDERFLOW -94
#define LIBCCP_PRIV_IS_NULL -95
#define LIBCCP_PROG_IS_NULL -96

// Fallback timer
#define LIBCCP_FALLBACK_TIMED_OUT -101
/********************************end*********************************/
/***********************#include "ccp_error.h"***********************/
/********************************************************************/

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
/********************************end*********************************/
/*************************#include "types.h"*************************/
/********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Datapaths must support these measurement primitives.
 * Each value is reported *per invocation*. 
 *
 * n.b. Ideally, an invocation is every packet, but datapaths might choose to call
 * ccp_invoke() less often.
 */
struct ccp_primitives {
    // newly acked, in-order bytes
    u32 bytes_acked;
    // newly acked, in-order packets
    u32 packets_acked;
    // out-of-order bytes
    u32 bytes_misordered;
    // out-of-order packets
    u32 packets_misordered;
    // bytes corresponding to ecn-marked packets
    u32 ecn_bytes;
    // ecn-marked packets
    u32 ecn_packets;

    // an estimate of the number of packets lost
    u32 lost_pkts_sample;
    // whether a timeout was observed
    bool was_timeout;

    // a recent sample of the round-trip time
    u64 rtt_sample_us;
    // sample of the sending rate, bytes / s
    u64 rate_outgoing;
    // sample of the receiving rate, bytes / s
    u64 rate_incoming;
    // the number of actual bytes in flight
    u32 bytes_in_flight;
    // the number of actual packets in flight
    u32 packets_in_flight;
    // the target congestion window to maintain, in bytes
    u32 snd_cwnd;
    // target rate to maintain, in bytes/s
    u64 snd_rate;

    // amount of data available to be sent
    // NOT per-packet - an absolute measurement
    u32 bytes_pending;
};

// maximum string length for congAlg
#define  MAX_CONG_ALG_SIZE   64
/* Datapaths provide connection information to ccp_connection_start
 */
struct ccp_datapath_info {
    u32 init_cwnd;
    u32 mss;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
    char congAlg[MAX_CONG_ALG_SIZE];
};

/* 
 * CCP state per connection. 
 * impl is datapath-specific, the rest are internal to libccp
 * for example, the linux kernel datapath uses impl to store a pointer to struct sock
 */
struct ccp_connection {
    // the index of this array element
    u16 index;

    u64 last_create_msg_sent;

    // struct ccp_primitives is large; as a result, we store it inside ccp_connection to avoid
    // potential limitations in the datapath
    // datapath should update this before calling ccp_invoke()
    struct ccp_primitives prims;
    
    // constant flow-level information
    struct ccp_datapath_info flow_info;

    // private libccp state for the send machine and measurement machine
    void *state;

    // datapath-specific per-connection state
    void *impl;

    // pointer back to parent datapath that owns this connection
    struct ccp_datapath *datapath;
};

enum ccp_log_level {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

/*
 * Global CCP state provided by the datapath
 *
 * Callbacks:
 * 1. set_cwnd(): set the congestion window
 * 2. set_rate_abs(): set the rate
 *
 * Time functions 
 * 3. now(): return a notion of time.
 * 4. since_usecs(u32 then): elapsed microseconds since <then>.
 * 5. after_usecs(u32 usecs): return a time <usecs> microseconds in the future.
 *
 * Utility functions
 * 6.  send_msg(): send a message from datapath -> userspace CCP.
 * 7.  log(): (optional)
 */
struct ccp_datapath {
    // control primitives
    void (*set_cwnd)(struct ccp_connection *conn, u32 cwnd); 
    void (*set_rate_abs)(struct ccp_connection *conn, u32 rate);

    // IPC communication
    int (*send_msg)(struct ccp_datapath *dp, char *msg, int msg_size);

    // logging
    void (*log)(struct ccp_datapath *dp, enum ccp_log_level level, const char* msg, int msg_size);

    // time management
    u64 time_zero;
    u64 (*now)(void); // the current time in datapath time units
    u64 (*since_usecs)(u64 then); // elapsed microseconds since <then>
    u64 (*after_usecs)(u64 usecs); // <usecs> microseconds from now in datapath time units

    size_t max_connections;
    // list of active connections this datapath is handling
    struct ccp_connection* ccp_active_connections;

    u64 fto_us;
    u64 last_msg_sent;
    bool _in_fallback;

    size_t max_programs;
    // list of datapath programs
    void *programs;
    
    // datapath-specific global state
    void *impl;
};

/* Initialize CCP.
 *
 * This function should be called before any other libccp functions and ensures (as much as possible) 
 * that the datapath structure has been initialized correctly. 
 *
 * A valid ccp_datapath must contain:
 *   1. 6 callback functions: set_cwnd, set_rate_abs, send_msg, now, since_users, after_usecs
 *   2. an optional callback function for logging
 *   3. a pointer to memory allocated for a list of ccp_connection objects
 *      (as well as the number of connections it can hold)
 *   4. a fallback timeout value in microseconds (must be > 0)
 *
 * The id argument uniquely identifies this datapath.
 *
 * IMPORTANT: caller must allocate..
 * 1. ccp_datapath
 * 2. ccp_datapath.ccp_active_connections with enough space for `max_connections` `ccp_connections`
 * ccp_init has no way of checking if enough space has been allocated, so any memory oob errors are
 * likely a result not allocating enough space.
 *
 * If the userspace CCP process isn't listening, this function will have the same failure behavior and return value as send_msg.  
 * In this case, initialization is considered to not be complete, and the caller is expected to try again.
 *
 * This function returns 0 if the structure has been initialized correctly and a negative value
 * with an error code otherwise. 
 */
int ccp_init(struct ccp_datapath *dp, u32 id);

/* Free the global struct and map for ccp connections upon module unload.
 */
void ccp_free(struct ccp_datapath *datapath);

/* Upon a new flow starting,
 * put a new connection into the active connections list
 *
 * returns the index at which the connection was placed; this index shall be used as the CCP socket id
 * return 0 on error
 */
struct ccp_connection *ccp_connection_start(struct ccp_datapath *datapath, void *impl, struct ccp_datapath_info *flow_info);

/* Upon a connection ending,
 * free its slot in the connection map.
 */
void ccp_connection_free(struct ccp_datapath *datapath, u16 sid);

/* While a flow is active, look up its CCP connection information.
 */
struct ccp_connection *ccp_connection_lookup(struct ccp_datapath *datapath, u16 sid);

/* Get the implementation-specific state of the ccp_connection.
 */
void *ccp_get_impl(struct ccp_connection *conn);

void ccp_set_impl(
    struct ccp_connection *conn, 
    void *ptr
);

/* Callback to pass to IPC for incoming messages.
 * Cannot take ccp_connection as an argument, since it's a callback.
 * Therefore, must look up ccp_connction from socket_id.
 * buf: the received message, of size bufsize.
 */
int ccp_read_msg(
    struct ccp_datapath *datapath, 
    char *buf,
    int bufsize
);

/* Should be called along with the ACK clock.
 *
 * Will invoke the send and measurement machines.
 */
int ccp_invoke(struct ccp_connection *conn);

void _update_fto_timer(struct ccp_datapath *datapath);
bool _check_fto(struct ccp_datapath *datapath);
void _turn_off_fto_timer(struct ccp_datapath *datapath);

#ifdef __cplusplus
} // extern "C"
#endif
/********************************end*********************************/
/**********************#include "libccp/ccp.h"***********************/
/********************************************************************/

/********************************************************************/
/*******************************ccp.c********************************/
/*******************************begin********************************/

/********************************************************************/
/***********************#include "ccp_priv.h"************************/
/*******************************begin********************************/
//#include "ccp.h"
/********************************************************************/
/***********************#include "serialize.h"***********************/
/*******************************begin********************************/
//#include "types.h"
//#include "ccp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct __attribute__((packed, aligned(4))) CcpMsgHeader {
    u16 Type;
    u16 Len;
    u32 SocketId;
};

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf);

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr);

/* There are 4 message types (Type field in header)
 * CREATE and MEASURE are written from datapath to CCP
 * PATTERN and INSTALL_FOLD are received in datapath from CCP
 * 
 * Messages start with the header, then 
 * 1. fixed number of u32
 * 2. fixed number of u64
 * 3. bytes blob, flexible length
 */
#define  CREATE        0
#define  MEASURE       1
#define  INSTALL_EXPR  2
#define  UPDATE_FIELDS 3
#define  CHANGE_PROG   4
#define  READY         5

// Some messages contain strings.
#define  BIGGEST_MSG_SIZE  32678

// create messages are fixed length: header + 4 * 6 + 32
#define CREATE_MSG_SIZE     96
// size of report msg is approx MAX_REPORT_REG * 8 + 4 + 4
#define REPORT_MSG_SIZE     900
// ready message is just a u32.
#define READY_MSG_SIZE 12

// Some messages contain serialized fold instructions.
#define MAX_EXPRESSIONS    256 // arbitrary TODO: make configurable
#define MAX_INSTRUCTIONS   256 // arbitrary, TODO: make configurable
#define MAX_IMPLICIT_REG   6  // fixed number of implicit registers
#define MAX_REPORT_REG     110 // measure msg 110 * 8 + 4 + 4
#define MAX_CONTROL_REG    110 // arbitrary
#define MAX_TMP_REG        8
#define MAX_LOCAL_REG      8
#define MAX_MUTABLE_REG    222 // # report + # control + cwnd, rate registers

struct __attribute__((packed, aligned(4))) ReadyMsg {
    u32 id;
};

/* READY
 * id: The unique id of this datapath.
 */
int write_ready_msg(
    char *buf,
    int bufsize,
    u32 id
);

/* CREATE
 * congAlg: the datapath's requested congestion control algorithm (could be overridden)
 */
struct __attribute__((packed, aligned(4))) CreateMsg {
    u32 init_cwnd;
    u32 mss;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
    char congAlg[MAX_CONG_ALG_SIZE];
};

/* Write cr: CreateMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_create_msg(
    char *buf,
    int bufsize,
    u32 sid,
    struct CreateMsg cr
);

/* MEASURE
 * program_uid: unique id for the datapath program that generated this report,
 *              so that the ccp can use the corresponding scope
 * num_fields: number of returned fields,
 * bytes: the return registers of the installed fold function ([]uint64).
 *        there will be at most MAX_PERM_REG returned registers
 */
struct __attribute__((packed, aligned(4))) MeasureMsg {
    u32 program_uid;
    u32 num_fields;
    u64 fields[MAX_REPORT_REG];
};

/* Write ms: MeasureMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid,
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
);

/* INSTRUCTION
 * 1 u8 for opcode
 * 3 sets of {u8, u32} for each of the result register, left register and right register
 */
struct __attribute__((packed, aligned(4))) InstructionMsg {
    u8 opcode;
    u8 result_reg_type;
    u32 result_register;
    u8 left_reg_type;
    u32 left_register;
    u8 right_reg_type;
    u32 right_register;
};


/* ExpressionMsg: 4 u32s
 * start of expression condition instr ID
 * number of expression condition instrs
 * start of event body instr ID
 * number of event body instrs
 */
struct __attribute__((packed, aligned(4))) ExpressionMsg {
    u32 cond_start_idx;
    u32 num_cond_instrs;
    u32 event_start_idx;
    u32 num_event_instrs;
};

struct __attribute__((packed, aligned(4))) InstallExpressionMsgHdr {
    u32 program_uid;
    u32 num_expressions;
    u32 num_instructions;
};

/* return: size of InstallExpressionMsgHeader
 * copies from buffer into InstallExpressionMsgHdr struct.
 * also checks whether the number of instructions or expressions is too large.
 * InstallExprMessage:
 * {
 *  struct InstallExpressionMsgHeader (3 u32s)
 *  ExpressionMsg[num_expressions]
 *  InstructionMsg[num_instructions]
 * }
 */
int read_install_expr_msg_hdr(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsgHdr *expr_msg_info,
    char *buf
);

struct __attribute__((packed, aligned(1))) UpdateField {
    u8 reg_type;
    u32 reg_index;
    u64 new_value;
};

/* Fills in number of updates.
 * Check whether number of updates is too large.
 * Returns size of update field header: 1 u32
 * UpdateFieldsMsg:
 * {
 *  1 u32: num_updates
 *  UpdateField[num_updates]
 * }
 */
int check_update_fields_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    u32 *num_updates,
    char *buf
);

struct __attribute__((packed, aligned(1))) ChangeProgMsg {
    u32 program_uid;
    u32 num_updates;
};

int read_change_prog_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct ChangeProgMsg *change_prog,
    char *buf
);

#ifdef __cplusplus
} // extern "C"
#endif
/********************************end*********************************/
/***********************#include "serialize.h"***********************/
/********************************************************************/

/********************************************************************/
/****************************serialize.c*****************************/
/*******************************begin********************************/
//#include "serialize.h"
//#include "ccp.h"
//#include "ccp_priv.h"
//#include "ccp_error.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* (type, len, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (2B) | Uint32    |
 * | (2 B)    | (2 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */

/* We only read Install, Update, and Change Program messages.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf) {
    memcpy(hdr, buf, sizeof(struct CcpMsgHeader));

    switch (hdr->Type) {
    case INSTALL_EXPR:
        return sizeof(struct CcpMsgHeader);
    case UPDATE_FIELDS:
        return sizeof(struct CcpMsgHeader);
    case CHANGE_PROG:
        return sizeof(struct CcpMsgHeader);
    default:
        return LIBCCP_READ_INVALID_HEADER_TYPE;
    }
}

/* We only write Create, Ready, and Measure messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
    case READY:
        break;
    default:
        return LIBCCP_WRITE_INVALID_HEADER_TYPE;
    }

    if (bufsize < ((int)sizeof(struct CcpMsgHeader))) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    memcpy(buf, hdr, sizeof(struct CcpMsgHeader));
    return sizeof(struct CcpMsgHeader);
}

int write_ready_msg(
    char *buf,
    int bufsize,
    u32 id
) {
    struct CcpMsgHeader hdr;
    int ret;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(u32);

    hdr = (struct CcpMsgHeader) {
        .Type = READY,
        .Len = msg_len,
        .SocketId = 0
    };

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }

    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &id, sizeof(u32));
    return hdr.Len;
}

int write_create_msg(
    char *buf, 
    int bufsize,
    u32 sid, 
    struct CreateMsg cr
) {
    struct CcpMsgHeader hdr;
    int ret;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(struct CreateMsg);
    
    hdr = (struct CcpMsgHeader){
        .Type = CREATE, 
        .Len = msg_len,
        .SocketId = sid,
    };

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }
    
    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }
    
    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &cr, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid, 
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
) {
    int ret;
    struct MeasureMsg ms = {
        .program_uid = program_uid,
        .num_fields = num_fields,
    };
    
    // 4 bytes for num_fields (u32) and 4 for program_uid = 8
    u16 msg_len = sizeof(struct CcpMsgHeader) + 8 + ms.num_fields * sizeof(u64);
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = msg_len,
        .SocketId = sid,
    };
    
    // copy message fields into MeasureMsg struct
    if (msg_fields) {
      memcpy(ms.fields, msg_fields, ms.num_fields * sizeof(u64));
    }

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }

    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &ms, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int read_install_expr_msg_hdr(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsgHdr *expr_msg_info,
    char *buf
) {
    if (hdr->Type != INSTALL_EXPR) {
        return LIBCCP_INSTALL_TYPE_MISMATCH;
    } 

    if (expr_msg_info->num_expressions > MAX_EXPRESSIONS) {
        //libccp_warn("Program to install has too many expressions: %u\n", expr_msg_info->num_expressions);
        return LIBCCP_INSTALL_TOO_MANY_EXPR;
    }

    if (expr_msg_info->num_instructions > MAX_INSTRUCTIONS) {
        //libccp_warn("Program to install has too many instructions: %u\n", expr_msg_info->num_instructions);
        return LIBCCP_INSTALL_TOO_MANY_INSTR;
    }
    memcpy(expr_msg_info, buf, sizeof(struct InstallExpressionMsgHdr));
    return sizeof(struct InstallExpressionMsgHdr);

}

int check_update_fields_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    u32 *num_updates,
    char *buf
) {
    if (hdr->Type != UPDATE_FIELDS) {
        //libccp_warn("check_update_fields_msg: hdr.Type != UPDATE_FIELDS");
        return LIBCCP_UPDATE_TYPE_MISMATCH;
    }

    *num_updates = (u32)*buf;
    if (*num_updates > MAX_MUTABLE_REG) {
        //libccp_warn("Too many updates!: %u\n", *num_updates);
        return LIBCCP_UPDATE_TOO_MANY;
    }
    return sizeof(u32);
}

int read_change_prog_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct ChangeProgMsg *change_prog,
    char *buf
) {
    if (hdr->Type != CHANGE_PROG) {
        //libccp_warn("read_change_prog_msg: hdr.Type != CHANGE_PROG");
        return LIBCCP_CHANGE_TYPE_MISMATCH;
    }

    memcpy(change_prog, buf, sizeof(struct ChangeProgMsg));
    if (change_prog->num_updates > MAX_MUTABLE_REG) {
        //libccp_warn("Too many updates sent with change prog: %u\n", change_prog->num_updates);
        return LIBCCP_CHANGE_TOO_MANY;
    }
    return sizeof(struct ChangeProgMsg);
}
/********************************end*********************************/
/****************************serialize.c*****************************/
/********************************************************************/

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdio.h>
#endif

#ifdef __KERNEL__
#define FMT_U64 "%llu"
#define FMT_U32 "%lu"
#else
#if defined(__APPLE__)
#define FMT_U64 "%llu"
#else
#define FMT_U64 "%lu"
#endif
#define FMT_U32 "%u"
#endif

#ifdef __KERNEL__
    #define __INLINE__       inline
    #define __CALLOC__(num_elements, block_size) kcalloc(num_elements, block_size, GFP_KERNEL)
    #define __FREE__(ptr)    kfree(ptr)
    #define CAS(a,o,n)       cmpxchg(a,o,n) == o
#else
    #define __INLINE__
    #define __CALLOC__(num_elements, block_size) calloc(num_elements, block_size)
    #define __FREE__(ptr)    free(ptr)
    #define CAS(a,o,n)       __sync_bool_compare_and_swap(a,o,n)
#endif

#define log_fmt(level, fmt, args...) {\
    char msg[80]; \
    int __ok = snprintf((char*) &msg, 80, fmt, ## args); \
    if (__ok >= 0) { \
        datapath->log(datapath, level, (const char*) &msg, __ok); \
    } \
}

// __LOG_INFO__ is default
#define libccp_trace(fmt, args...)
#define libccp_debug(fmt, args...)
#define libccp_info(fmt, args...) log_fmt(INFO, fmt, ## args)
#define libccp_warn(fmt, args...) log_fmt(WARN, fmt, ## args)
#define libccp_error(fmt, args...) log_fmt(ERROR, fmt, ## args)

#ifdef __LOG_TRACE__
#undef libccp_trace
#define libccp_trace(fmt, args...) log_fmt(TRACE, fmt, ## args)
#undef libccp_debug
#define libccp_debug(fmt, args...) log_fmt(DEBUG, fmt, ## args)
#endif

#ifdef __LOG_DEBUG__
#undef libccp_debug
#define libccp_debug(fmt, args...) log_fmt(DEBUG, fmt, ## args)
#endif

#ifdef __LOG_WARN__
#undef libccp_info
#define libccp_info(fmt, args...)
#endif
#ifdef __LOG_ERROR__
#undef libccp_info
#define libccp_info(fmt, args...)
#undef libccp_warn
#define libccp_warn(fmt, args...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Triggers the state machine that goes through the expressions and evaluates conditions if true.
 * Should be called on each tick of the ACK clock; i.e. every packet.
 */
int state_machine(
    struct ccp_connection *conn
);

struct Register {
    u8 type;
    int index;
    u64 value;
};

struct Instruction64 {
    u8 op;
    struct Register rRet;
    struct Register rLeft;
    struct Register rRight;
};

/*  Expression contains reference to:
 *  instructions for condition
 *  instructions for body of expression
 */
struct Expression {
    u32 cond_start_idx;
    u32 num_cond_instrs;
    u32 event_start_idx;
    u32 num_event_instrs;
};

/*  Entire datapath program
 *  a set of expressions (conditions)
 *  a set of instructions
 */
struct DatapathProgram {
    u8 num_to_return;
    u16 index; // index in array
    u32 program_uid; // program uid assigned by CCP agent
    u32 num_expressions;
    u32 num_instructions;
    struct Expression expressions[MAX_EXPRESSIONS];
    struct Instruction64 fold_instructions[MAX_INSTRUCTIONS];
};

int read_expression(
    struct Expression *ret,
    struct ExpressionMsg *msg
);

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
);

struct register_file {
    // report and control registers - users send a DEF for these
    u64 report_registers[MAX_REPORT_REG]; // reported variables, reset to DEF value upon report
    u64 control_registers[MAX_CONTROL_REG]; // extra user defined variables, not reset on report

    // tmp, local and implicit registers
    u64 impl_registers[MAX_IMPLICIT_REG]; // stores special flags and variables
    u64 tmp_registers[MAX_TMP_REG]; // used for temporary calculation in instructions
    u64 local_registers[MAX_LOCAL_REG]; // for local variables within a program - created in a bind in a when clause
};

struct staged_update {
    bool control_is_pending[MAX_CONTROL_REG];
    u64 control_registers[MAX_CONTROL_REG];
    bool impl_is_pending[MAX_IMPLICIT_REG];
    u64 impl_registers[MAX_IMPLICIT_REG];
};

/* libccp Private State
 * struct ccp_connection has a void* state to store libccp's state
 * libccp internally casts this to a struct ccp_priv_state*.
 */
struct ccp_priv_state {
    bool sent_create;
    u64 implicit_time_zero; // can be reset

    u16 program_index; // index into program array
    int staged_program_index;

    struct register_file registers;
    struct staged_update pending_update;
};

/*
 * Resets a specific register's value in response to an update field message.
 * Needs pointer to ccp_connection in case message is for updating the cwnd or rate.
 */
int update_register(
    struct ccp_connection* conn,
    struct ccp_priv_state *state,
    struct UpdateField *update_field
);

/* Reset the output state registers to their default values
 * according to the DEF instruction preamble.
 */
void reset_state(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Initializes the control registers to their default values
 * according to the DEF instruction preamble.
 */
void init_register_state(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Reset the implicit time registers to count from datapath->now()
 */
void reset_time(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Initialize send machine and measurement machine state in ccp_connection.
 * Called from ccp_connection_start()
 */
int init_ccp_priv_state(struct ccp_datapath *datapath, struct ccp_connection *conn);
/* Free the allocated flow memory.
 * Call when the flow has ended.
 */
void free_ccp_priv_state(struct ccp_connection *conn);

// send create message to CCP
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
);

// send measure message to CCP
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
);

/* Retrieve the private state from ccp_connection.
 */
struct ccp_priv_state *get_ccp_priv_state(struct ccp_connection *conn);

/* Lookup a datapath program, available to all flows
 */
struct DatapathProgram* datapath_program_lookup(struct ccp_datapath *datapath, u16 pid);

/*
 * Reserved Implicit Registers
 */
#define EXPR_FLAG_REG             0
#define SHOULD_FALLTHROUGH_REG    1
#define SHOULD_REPORT_REG         2
#define US_ELAPSED_REG            3
#define CWND_REG                  4
#define RATE_REG                  5

/*
 * Primitive registers
 */
#define  ACK_BYTES_ACKED          0
#define  ACK_BYTES_MISORDERED     1
#define  ACK_ECN_BYTES            2
#define  ACK_ECN_PACKETS          3
#define  ACK_LOST_PKTS_SAMPLE     4
#define  ACK_NOW                  5
#define  ACK_PACKETS_ACKED        6
#define  ACK_PACKETS_MISORDERED   7
#define  FLOW_BYTES_IN_FLIGHT     8
#define  FLOW_BYTES_PENDING       9
#define  FLOW_PACKETS_IN_FLIGHT   10
#define  FLOW_RATE_INCOMING       11
#define  FLOW_RATE_OUTGOING       12
#define  FLOW_RTT_SAMPLE_US       13
#define  FLOW_WAS_TIMEOUT         14

/*
 * Operations
 */
#define    ADD        0
#define    BIND       1
#define    DEF        2
#define    DIV        3
#define    EQUIV      4
#define    EWMA       5
#define    GT         6
#define    IF         7
#define    LT         8
#define    MAX        9
#define    MAXWRAP    10
#define    MIN        11
#define    MUL        12
#define    NOTIF      13
#define    SUB        14
#define    MAX_OP     15

// types of registers
#define NONVOLATILE_CONTROL_REG 0
#define IMMEDIATE_REG           1
#define IMPLICIT_REG            2
#define LOCAL_REG               3
#define PRIMITIVE_REG           4
#define VOLATILE_REPORT_REG     5
#define NONVOLATILE_REPORT_REG  6
#define TMP_REG                 7
#define VOLATILE_CONTROL_REG    8

#ifdef __cplusplus
} // extern "C"
#endif
/********************************end*********************************/
/***********************#include "ccp_priv.h"************************/
/********************************************************************/

/********************************************************************/
/*****************************ccp_priv.c*****************************/
/*******************************begin********************************/
//#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy,memset
#else
#include <stdlib.h>
#include <string.h>
#endif

int init_ccp_priv_state(struct ccp_datapath *datapath, struct ccp_connection *conn) {
    struct ccp_priv_state *state;

    conn->state = __CALLOC__(1, sizeof(struct ccp_priv_state));
    state = (struct ccp_priv_state*) conn->state;

    state->sent_create = false;
    state->implicit_time_zero = datapath->time_zero;
    state->program_index = 0;
    state->staged_program_index = -1;

    conn->datapath = datapath;

    return 0;
}

void free_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    __FREE__(state);
}

__INLINE__ struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*) conn->state;
}

// lookup datapath program using program ID
// returns  NULL on error
struct DatapathProgram* datapath_program_lookup(struct ccp_datapath *datapath, u16 pid) {
    struct DatapathProgram *prog;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;

    // bounds check
    if (pid == 0) {
        libccp_warn("no datapath program set\n");
        return NULL;
    } else if (pid > datapath->max_programs) {
        libccp_warn("program index out of bounds: %d\n", pid);
        return NULL;
    }

    prog = &programs[pid-1];
    if (prog->index != pid) {
        libccp_warn("index mismatch: pid %d, index %d", pid, prog->index);
        return NULL;
    }

    return prog;

}
/********************************end*********************************/
/*****************************ccp_priv.c*****************************/
/********************************************************************/

/********************************************************************/
/*****************************machine.c******************************/
/*******************************begin********************************/
//#include "ccp_priv.h"
//#include "ccp_error.h"

/*
 * CCP Send State Machine
 *
 * Userspace CCP algorithms specify "expressions".
 * Expressions are conditions (a series of instructions that evaluate to a boolean expression)
 * followed by a set of instructions to execute if that event is true
 */

#define CCP_FRAC_DENOM 10

/*
 * Aggregator functions
 * Corresponds to operations sent down in instruction messages
 * Bind, ifcnt, and ifnotcnt are directly inline
 */
static u64 myadd64(u64 a, u64 b) {
    return a + b;
}

static u64 mydiv64(u64 a, u64 b) {
    return a/b;
}

static u64 myequiv64(u64 a, u64 b) {
    return ( a == b );
}

static u64 myewma64(u64 a, u64 b, u64 c) {
    u64 num;
    u64 old = a * b;
    u64 new_val = ( CCP_FRAC_DENOM - a ) * c;
    if ( b == 0 ) {
        return c;
    }
    num = old + new_val;
    return num/CCP_FRAC_DENOM;
}

static u64 mygt64(u64 a, u64 b) {
    return ( a > b );
}

static u64 mylt64(u64 a, u64 b) {
    return ( a < b );
}


// raw difference from left -> right, provided you're walking in direction left -> right
static u32 dif32(u32 left, u32 right) {
    u32 max32 = ((u32)~0U);
    if ( right > left ) {
        return ( right - left );
    }
    // left -> max -> right
    return (max32 - left) + right;
}

/* must handle integer wraparound*/
static u64 mymax64_wrap(u64 a, u64 b) {
    u32 a32 = (u32)a;
    u32 b32 = (u32)b;
    u32 left_to_right = dif32(a32, b32);
    u32 right_to_left = dif32(b32, a32);
    // 0 case
    if ( a == 0 ) {
        return b;
    }
    if ( b == 0 ) {
        return a;
    }
    // difference from b -> a is shorter than difference from a -> b: so order is (b,a)
    if ( right_to_left < left_to_right ) {
        return (u64)a32;
    }
    // else difference from a -> b is sorter than difference from b -> a: so order is (a,b)
    return (u64)b32;
}

static u64 mymax64(u64 a, u64 b) {
    if ( a > b ) {
        return a;
    }
    return b;
}

static u64 mymin64(u64 a, u64 b) {
    if ( a < b ) {
        return a;
    }
    return b;
}

static u64 mymul64(u64 a, u64 b) {
    return a*b;
}

static u64 mysub64(u64 a, u64 b) {
    return a - b;
}

/*
 * Read Operations from operation messages
 */
static int read_op(struct Instruction64* instr, u8 opcode) {
    if (opcode >= MAX_OP) {
        return LIBCCP_READ_INVALID_OP;
    }
    instr->op = opcode;
    return LIBCCP_OK;
}

/*
 * Deserialize registers sent down as u32
 * u32 is necessary for value as it could be an immediate register
 */
static int deserialize_register(struct Register *ret, u8 reg_type, u32 reg_value) {
    switch (reg_type) {
       case IMMEDIATE_REG: // immediate - store in value
            ret->type = (int)IMMEDIATE_REG;
            ret->value = (u64)reg_value;
            return 0;
        case NONVOLATILE_CONTROL_REG: // control register
            ret->type = (int)NONVOLATILE_CONTROL_REG;
            break;
        case VOLATILE_CONTROL_REG: // control register
            ret->type = (int)VOLATILE_CONTROL_REG;
            break;
        case IMPLICIT_REG: // implicit
            ret->type = (int)IMPLICIT_REG;
            break;
        case PRIMITIVE_REG: // primitive
            ret->type = (int)PRIMITIVE_REG;
            break;
        case VOLATILE_REPORT_REG: // output/permanent
            ret->type = (int)VOLATILE_REPORT_REG;
            break;
        case NONVOLATILE_REPORT_REG: // output/permanent
            ret->type = (int)NONVOLATILE_REPORT_REG;
            break;
        case TMP_REG: // temporary register
            ret->type = (int)TMP_REG;
            break;
        case LOCAL_REG: // local register
            ret->type = (int)LOCAL_REG;
            break;
        default:
            return -1;
    }

    ret->index = (int)reg_value;
    return 0;
}

/*
 * Write into specified registers
 * Only allowed to write into NONVOLATILE_REPORT_REG, VOLATILE_REPORT_REG, TMP_REG, LOCAL_REG
 * and some of the IMPL_REG: EXPR_FLAG_REG, CWND_REG, RATE_REG, SHOULD_REPORT_REG
 */
static void write_reg(struct ccp_datapath *datapath, struct ccp_priv_state *state, u64 value, struct Register reg) {
    switch (reg.type) {
        case NONVOLATILE_REPORT_REG:
        case VOLATILE_REPORT_REG:
            if (reg.index >= 0 && reg.index < MAX_REPORT_REG) {
                state->registers.report_registers[reg.index] = value;
            }
            break;
        case TMP_REG:
            if (reg.index >= 0 && reg.index < MAX_TMP_REG) {
                state->registers.tmp_registers[reg.index] = value;
            }
            break;
        case LOCAL_REG:
            if (reg.index >= 0 && reg.index < MAX_LOCAL_REG) {
                state->registers.local_registers[reg.index] = value;
            }
            break;
        case IMPLICIT_REG: // cannot write to US_ELAPSED reg
            if (reg.index == EXPR_FLAG_REG || reg.index == CWND_REG || reg.index == RATE_REG || reg.index == SHOULD_REPORT_REG || reg.index == SHOULD_FALLTHROUGH_REG ) {
                state->registers.impl_registers[reg.index] = value;
            } else if (reg.index == US_ELAPSED_REG) {
                // set micros register to this value, and datapath start time to be time before now
                state->implicit_time_zero = datapath->now() - value;
                state->registers.impl_registers[US_ELAPSED_REG] = value;
            }
            break;
        case VOLATILE_CONTROL_REG:
        case NONVOLATILE_CONTROL_REG:
            if (reg.index >= 0 && reg.index < MAX_CONTROL_REG) {
                state->registers.control_registers[reg.index] = value; 
            }
        default:
            break;
    }
}

/*
 * Read specified register
 */
static u64 read_reg(struct ccp_datapath *datapath, struct ccp_priv_state *state, struct ccp_primitives* primitives, struct Register reg) {
    switch (reg.type) {
        case IMMEDIATE_REG:
            return reg.value;
        case NONVOLATILE_REPORT_REG:
        case VOLATILE_REPORT_REG:
            return state->registers.report_registers[reg.index];
        case NONVOLATILE_CONTROL_REG:
        case VOLATILE_CONTROL_REG:
            return state->registers.control_registers[reg.index];
        case TMP_REG:
            return state->registers.tmp_registers[reg.index];
        case LOCAL_REG:
            return state->registers.local_registers[reg.index];
        case PRIMITIVE_REG:
            switch (reg.index) {
                case ACK_BYTES_ACKED:
                    return primitives->bytes_acked;
                case ACK_PACKETS_ACKED:
                    return primitives->packets_acked;
                case ACK_BYTES_MISORDERED:
                    return primitives->bytes_misordered;
                case ACK_PACKETS_MISORDERED:
                    return primitives->packets_misordered;
                case ACK_ECN_BYTES:
                    return primitives->ecn_bytes;
                case ACK_ECN_PACKETS:
                    return primitives->ecn_packets;
                case ACK_LOST_PKTS_SAMPLE:
                    return primitives->lost_pkts_sample;
                case FLOW_WAS_TIMEOUT:
                    return primitives->was_timeout;
                case FLOW_RTT_SAMPLE_US:
                    if (primitives->rtt_sample_us == 0) {
                        return ((u64)~0U);
                    } else {
                        return primitives->rtt_sample_us;
                    }
                case FLOW_RATE_OUTGOING:
                    return primitives->rate_outgoing;
                case FLOW_RATE_INCOMING:
                    return primitives->rate_incoming;
                case FLOW_BYTES_IN_FLIGHT:
                    return primitives->bytes_in_flight;
                case FLOW_PACKETS_IN_FLIGHT:
                    return primitives->packets_in_flight;
                case ACK_NOW:
                    return datapath->since_usecs(datapath->time_zero);
                case FLOW_BYTES_PENDING:
                    return primitives->bytes_pending;
                default:
                    return 0;
            }
            break;
        case IMPLICIT_REG:
            return state->registers.impl_registers[reg.index];
            break;
        default:
            return 0;
    }
}

/*
 * Process instruction at specfied index 
 */
static int process_instruction(struct ccp_datapath *datapath, struct DatapathProgram *program, int instr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    //struct DatapathProgram* program = datapath_program_lookup(state->program_index);
    struct Instruction64 current_instruction = program->fold_instructions[instr_index];
    u64 arg0, arg1, arg2, result; // extra arg0 for ewma, if, not if

    arg1 = read_reg(datapath, state, primitives, current_instruction.rLeft);
    arg2 = read_reg(datapath, state, primitives, current_instruction.rRight);
    switch (current_instruction.op) {
        case ADD:
            libccp_trace("ADD  " FMT_U64 " + " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, myadd64(arg1, arg2)); 
            result = myadd64(arg1, arg2);
            if (result < arg1) {
                libccp_warn("ERROR! Integer overflow: " FMT_U64 " + " FMT_U64 "\n", arg1, arg2);
                return LIBCCP_ADD_INT_OVERFLOW;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case DIV:
            libccp_trace("DIV  " FMT_U64 " / " FMT_U64 " = ", arg1, arg2);
            if (arg2 == 0) {
                libccp_warn("ERROR! Attempt to divide by 0: " FMT_U64 " / " FMT_U64 "\n", arg1, arg2);
                return LIBCCP_DIV_BY_ZERO;
            } else {
                libccp_trace("" FMT_U64 "\n", mydiv64(arg1, arg2));
                write_reg(datapath, state, mydiv64(arg1, arg2), current_instruction.rRet);
            }
            break;
        case EQUIV:
            libccp_trace("EQV  " FMT_U64 " == " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, myequiv64(arg1, arg2));
            write_reg(datapath, state, myequiv64(arg1, arg2), current_instruction.rRet);
            break;
        case EWMA: // arg0 = current, arg2 = new, arg1 = constant
            arg0 = read_reg(datapath, state, primitives, current_instruction.rRet); // current state
            write_reg(datapath, state, myewma64(arg1, arg0, arg2), current_instruction.rRet);
            break;
        case GT:
            libccp_trace("GT   " FMT_U64 " > " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mygt64(arg1, arg2));
            write_reg(datapath, state, mygt64(arg1, arg2), current_instruction.rRet);
            break;
        case LT:
            libccp_trace("LT   " FMT_U64 " > " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mylt64(arg1, arg2));
            write_reg(datapath, state, mylt64(arg1, arg2), current_instruction.rRet);
            break;
        case MAX:
            libccp_trace("MAX  " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymax64(arg1, arg2));
            write_reg(datapath, state, mymax64(arg1, arg2), current_instruction.rRet);
            break;
        case MIN:
            libccp_trace("MIN  " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymin64(arg1, arg2));
            write_reg(datapath, state, mymin64(arg1, arg2), current_instruction.rRet);
            break;
        case MUL:
            libccp_trace("MUL  " FMT_U64 " * " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, mymul64(arg1, arg2));
            result = mymul64(arg1, arg2);
            if (result < arg1 && arg2 > 0) {
                libccp_error("ERROR! Integer overflow: " FMT_U64 " * " FMT_U64 "\n", arg1, arg2);
                return LIBCCP_MUL_INT_OVERFLOW;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case SUB:
            libccp_trace("SUB  " FMT_U64 " - " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, mysub64(arg1, arg2));
            result = mysub64(arg1, arg2);
            if (result > arg1) {
                libccp_error("ERROR! Integer underflow: " FMT_U64 " - " FMT_U64 "\n", arg1, arg2);
                return LIBCCP_SUB_INT_UNDERFLOW;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case MAXWRAP:
            libccp_trace("MAXW " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymax64_wrap(arg1, arg2));
            write_reg(datapath, state, mymax64_wrap(arg1, arg2), current_instruction.rRet);
            break;
        case IF: // if arg1 (rLeft), stores rRight in rRet
            libccp_trace("IF   " FMT_U64 " : r" FMT_U64 " -> r" FMT_U64 "\n", arg1, arg2, current_instruction.rRet.value);
            if (arg1) {
                write_reg(datapath, state, arg2, current_instruction.rRet);
            }
            break;
        case NOTIF:
            libccp_trace("!IF  " FMT_U64 " : r" FMT_U64 " -> r" FMT_U64 "\n", arg1, arg2, current_instruction.rRet.value);
            if (arg1 == 0) {
                write_reg(datapath, state, arg2, current_instruction.rRet);
            }
            break;
        case BIND: // take arg2, and put it in rRet
            libccp_trace("BIND r%d: " FMT_U64 " -> " FMT_U64 "\n", current_instruction.rRet.index, current_instruction.rRet.value, arg2);
            write_reg(datapath, state, arg2, current_instruction.rRet);
            break;
        default:
            libccp_debug("UNKNOWN OP %d\n", current_instruction.op);
            break;
    }
    return LIBCCP_OK;

}

/*
 * Process a single event - check if condition is true, and execute event body if so
 */
static int process_expression(struct ccp_datapath *datapath, struct DatapathProgram *program, int expr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    //struct DatapathProgram* program = datapath_program_lookup(state->program_index);
    struct Expression *expression = &(program->expressions[expr_index]);
    u8 idx;
    int ret;
    libccp_trace("when #%d {\n", expr_index);
    for (idx=expression->cond_start_idx; idx<(expression->cond_start_idx + expression->num_cond_instrs); idx++) {
       ret = process_instruction(datapath, program, idx, state, primitives);
       if (ret < 0) {
         return ret;
       }
    }
    libccp_trace("} => " FMT_U64 "\n", state->registers.impl_registers[EXPR_FLAG_REG]);

    // flag from event is promised to be stored in this implicit register
    if (state->registers.impl_registers[EXPR_FLAG_REG] ) {
        for (idx = expression->event_start_idx; idx<(expression->event_start_idx + expression->num_event_instrs ); idx++) {
            ret = process_instruction(datapath, program, idx, state, primitives);
            if (ret < 0) {
                return ret;
            }
        }
    }

    return LIBCCP_OK;
}

/*
 * Read instructions into an instruction struct
 */
int read_instruction(
    struct Instruction64 *instr,
    struct InstructionMsg *msg
) {
    int reg;
    reg = read_op(instr, msg->opcode);
    if (reg < 0) {
        return reg;
    }
    
    // check if the reg type is IMMEDIATE or PRIMITIVE
    if (msg->result_reg_type == IMMEDIATE_REG || msg->result_reg_type == PRIMITIVE_REG) {
        return LIBCCP_READ_REG_NOT_ALLOWED;
    }

    reg = deserialize_register(&instr->rRet, msg->result_reg_type, msg->result_register);
    if (reg < 0) {
        return LIBCCP_READ_INVALID_RETURN_REG;
    }

    reg = deserialize_register(&instr->rLeft, msg->left_reg_type, msg->left_register);
    if (reg < 0) {
        return LIBCCP_READ_INVALID_LEFT_REG;
    }

    reg = deserialize_register(&instr->rRight, msg->right_reg_type, msg->right_register);
    if (reg < 0) {
        return LIBCCP_READ_INVALID_RIGHT_REG;
    }

    return reg;
}

/*
 * Read expression msg into expression struct
 */
int read_expression(
    struct Expression *expr,
    struct ExpressionMsg *msg
) {
    expr->cond_start_idx = msg->cond_start_idx;
    expr->num_cond_instrs = msg->num_cond_instrs;
    expr->event_start_idx = msg->event_start_idx;
    expr->num_event_instrs = msg->num_event_instrs;
    return LIBCCP_OK;
}

/*
 * Resets all permanent registers to the DEF values
 */
void reset_state(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    u8 i;
    struct DatapathProgram* program = datapath_program_lookup(datapath, state->program_index);
    if (program == NULL) {
        libccp_info("Cannot reset state because program is NULL\n");
        return;
    }
    struct Instruction64 current_instruction;
    u8 num_to_return = 0;

    // go through all the DEF instructions, and reset all VOLATILE_REPORT_REG variables
    for (i = 0; i < program->num_instructions; i++) {
        current_instruction = program->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
                // This only applies to REPORT_REG and volatile CONTROL_REG.
                if (current_instruction.rLeft.type != NONVOLATILE_REPORT_REG && 
                    current_instruction.rLeft.type != VOLATILE_REPORT_REG && 
                    current_instruction.rLeft.type != VOLATILE_CONTROL_REG) {
                    continue;
                }
                
                // We report both NONVOLATILE_REPORT_REG and VOLATILE_REPORT_REG.
                if (current_instruction.rLeft.type != VOLATILE_CONTROL_REG) {
                    num_to_return += 1;
                }

                // We don't reset NONVOLATILE_REPORT_REG
                if (current_instruction.rLeft.type == NONVOLATILE_REPORT_REG) {
                    continue;
                }

                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(datapath, state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(datapath, state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                break;
            default:
                // DEF instructions are only at the beginnning
                // Once we see a non-DEF, can stop.
                program->num_to_return = num_to_return;
                return; 
        }
    }    
}

void init_register_state(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    u8 i;
    struct Instruction64 current_instruction;
    struct DatapathProgram* program = datapath_program_lookup(datapath, state->program_index);
    if (program == NULL) {
        libccp_info("Cannot init register state because program is NULL\n");
        return;
    }

    // go through all the DEF instructions, and reset all nonvolatile CONTROL_REG and REPORT_REG variables
    for (i = 0; i < program->num_instructions; i++) {
        current_instruction = program->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
                if (current_instruction.rLeft.type != NONVOLATILE_CONTROL_REG && current_instruction.rLeft.type != NONVOLATILE_REPORT_REG) {
                    continue;
                }
                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(datapath, state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(datapath, state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                break;
            default:
                return; 
        }
    }    
}

/*
 * Resets implicit registers associated with US_ELAPSED
 */
void reset_time(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    // reset the ns elapsed register to register now as 0
    state->implicit_time_zero = datapath->now();
    state->registers.impl_registers[US_ELAPSED_REG] = 0;
}

/*
 * Before state machine, reset  some of the implicit registers
 */
static __INLINE__ void reset_impl_registers(struct ccp_priv_state *state) {
    state->registers.impl_registers[EXPR_FLAG_REG] = 0;
    state->registers.impl_registers[SHOULD_FALLTHROUGH_REG] = 0;
    state->registers.impl_registers[SHOULD_REPORT_REG] = 0;
}

/*
 * Called from ccp_invoke
 * Evaluates all the current expressions
 */
int state_machine(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    struct ccp_datapath *datapath = conn->datapath;
    if (state == NULL) {
        libccp_warn("CCP priv state is null");
        return LIBCCP_PRIV_IS_NULL;
    }
    struct DatapathProgram* program = datapath_program_lookup(conn->datapath, state->program_index);
    if (program == NULL) {
        libccp_warn("Datapath program is null");
        return LIBCCP_PROG_IS_NULL;
    }
    struct ccp_primitives* primitives = &conn->prims;
    u32 i;
    int ret;
    u64 implicit_now;
    
    // reset should Report, should fall through, and event expression
    reset_impl_registers(state);

    // update the US_ELAPSED registers
    implicit_now = datapath->since_usecs(state->implicit_time_zero);
    state->registers.impl_registers[US_ELAPSED_REG] = implicit_now;
    
    libccp_trace(">>> program starting [sid=%d] <<<\n", conn->index);
    // cycle through expressions, and process instructions
    for (i=0; i < program->num_expressions; i++) {
        ret = process_expression(datapath, program, i, state, primitives);
        if (ret < 0) {
            libccp_trace(">>> program finished [sid=%d] [ret=-1] <<<\n\n", conn->index);
            return ret;
        }

        // break if the expression is true and fall through is NOT true
        if ((state->registers.impl_registers[EXPR_FLAG_REG]) && !(state->registers.impl_registers[SHOULD_FALLTHROUGH_REG])) {
            break;
        }
        libccp_trace("[sid=%d] fallthrough...\n", conn->index);
    }
    // set rate and cwnd from implicit registers
    if (state->registers.impl_registers[CWND_REG] > 0) {
        libccp_debug("[sid=%d] setting cwnd after program: " FMT_U64 "\n", conn->index, state->registers.impl_registers[CWND_REG]);
        datapath->set_cwnd(conn, state->registers.impl_registers[CWND_REG]);
    }

    if (state->registers.impl_registers[RATE_REG] != 0) {
        libccp_debug("[sid=%d] setting rate after program: " FMT_U64 "\n", conn->index, state->registers.impl_registers[CWND_REG]);
        datapath->set_rate_abs(conn, state->registers.impl_registers[RATE_REG]);
    }

    // if we should report, report and reset state
    if (state->registers.impl_registers[SHOULD_REPORT_REG]) {
        send_measurement(conn, program->program_uid, state->registers.report_registers, program->num_to_return);
        reset_state(conn->datapath, state);
    }

    libccp_trace(">>> program finished [sid=%d] [ret=0] <<<\n\n", conn->index);
    return LIBCCP_OK;
}
/********************************end*********************************/
/*****************************machine.c******************************/
/********************************************************************/

//#include "ccp_error.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define CREATE_TIMEOUT_US 100000 // 100 ms

/* CCP Datapath Connection Map
 *
 * When we receive a message from userspace CCP, we are not
 * in the flow context and need to access state (e.g. primitives) for
 * the appropriate connection.
 *
 * So, we maintain a map of ccp sock_id -> flow state information.
 * This flow state information is the API that datapaths must implement to support CCP.
 */

/* Drop log messages if no log output is defined.
 */
void __INLINE__ null_log(struct ccp_datapath *dp, enum ccp_log_level level, const char* msg, int msg_size) {
    (void)(dp);
    (void)(level);
    (void)(msg);
    (void)(msg_size);
}

int ccp_init(struct ccp_datapath *datapath, u32 id) {
    int ok;
    char ready_msg[READY_MSG_SIZE];
    libccp_trace("ccp_init");
    if (
        datapath                         ==  NULL  ||
        datapath->set_cwnd               ==  NULL  ||
        datapath->set_rate_abs           ==  NULL  ||
        datapath->send_msg               ==  NULL  ||
        datapath->now                    ==  NULL  ||
        datapath->since_usecs            ==  NULL  ||
        datapath->after_usecs            ==  NULL  ||
        datapath->ccp_active_connections ==  NULL  ||
        datapath->max_connections        ==  0     ||
        datapath->max_programs           ==  0     ||
        datapath->fto_us                 ==  0
    ) {
        return LIBCCP_MISSING_ARG;
    }

    if (datapath->log == NULL) {
        datapath->log = &null_log;
    }

    // send ready message
    ok = write_ready_msg(ready_msg, READY_MSG_SIZE, id);
    if (ok < 0) {
        libccp_error("could not serialize ready message")
        return ok;
    }

    ok = datapath->send_msg(datapath, ready_msg, READY_MSG_SIZE);
    if (ok < 0) {
        libccp_warn("could not send ready message: %d", ok)
    }

    libccp_trace("wrote ready msg")
    datapath->programs = __CALLOC__(datapath->max_programs, sizeof(struct DatapathProgram));
    datapath->time_zero = datapath->now();
    datapath->last_msg_sent = 0;
    datapath->_in_fallback = false;
    return LIBCCP_OK;
}

void ccp_free(struct ccp_datapath *datapath) {
  __FREE__(datapath->programs);
}

void ccp_conn_create_success(struct ccp_priv_state *state) {
    state->sent_create = true;
}

struct ccp_connection *ccp_connection_start(struct ccp_datapath *datapath, void *impl, struct ccp_datapath_info *flow_info) {
    int ret;
    u16 sid;
    struct ccp_connection *conn;

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < datapath->max_connections; sid++) {
        conn = &datapath->ccp_active_connections[sid];
        if (CAS(&(conn->index), 0, sid+1)) {
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= datapath->max_connections) {
        return NULL;
    }

    conn->impl = impl;
    memcpy(&conn->flow_info, flow_info, sizeof(struct ccp_datapath_info));

    init_ccp_priv_state(datapath, conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ret = send_conn_create(datapath, conn);
    if (ret < 0) {
        if (!datapath->_in_fallback) {
            libccp_warn("failed to send create message: %d\n", ret);
        }
        return conn;
    }

    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    ccp_conn_create_success(state);

    return conn;
}

__INLINE__ void *ccp_get_impl(struct ccp_connection *conn) {
    return conn->impl;
}

__INLINE__ void ccp_set_impl(struct ccp_connection *conn, void *ptr) {
    conn->impl = ptr;
}

int ccp_invoke(struct ccp_connection *conn) {
    int i;
    int ret = 0;
    struct ccp_priv_state *state;
    struct ccp_datapath *datapath;

    if (conn == NULL) {
        return LIBCCP_NULL_ARG;
    }

    datapath = conn->datapath;

    if (_check_fto(datapath)) {
        return LIBCCP_FALLBACK_TIMED_OUT;
    }

    state = get_ccp_priv_state(conn);

    if (!(state->sent_create)) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        libccp_trace("%s retx create message\n", __FUNCTION__);
        ret = send_conn_create(datapath, conn);
        if (ret < 0) {
            if (!datapath->_in_fallback) {
                libccp_warn("failed to retx create message: %d\n", ret);
            }
        } else {
            ccp_conn_create_success(state);
        }

        // TODO should we really be returning here? shouldn't we just keep going?
        return LIBCCP_OK;
    }

    // set cwnd and rate registers to what they are in the datapath
    libccp_trace("primitives (cwnd, rate): (" FMT_U32 ", " FMT_U64 ")\n", conn->prims.snd_cwnd, conn->prims.snd_rate);
    state->registers.impl_registers[CWND_REG] = (u64)conn->prims.snd_cwnd;
    state->registers.impl_registers[RATE_REG] = (u64)conn->prims.snd_rate;
    
    if (state->staged_program_index >= 0) {
        // change the program to this program, and reset the state
        libccp_debug("[sid=%d] Applying staged program change: %d -> %d\n", conn->index, state->program_index, state->staged_program_index); 
        state->program_index = state->staged_program_index;
        reset_state(conn->datapath, state);
        init_register_state(conn->datapath, state);
        reset_time(conn->datapath, state);
        state->staged_program_index = -1;
    }

    for (i = 0; i < MAX_CONTROL_REG; i++) {
        if (state->pending_update.control_is_pending[i]) {
            libccp_debug("[sid=%d] Applying staged field update: control reg %u (" FMT_U64 "->" FMT_U64 ") \n", 
                conn->index, i,
                state->registers.control_registers[i],
                state->pending_update.control_registers[i]
            );
            state->registers.control_registers[i] = state->pending_update.control_registers[i];
        }
    }

    if (state->pending_update.impl_is_pending[CWND_REG]) {
        libccp_debug("[sid=%d] Applying staged field update: cwnd reg <- " FMT_U64 "\n", conn->index, state->pending_update.impl_registers[CWND_REG]);
        state->registers.impl_registers[CWND_REG] = state->pending_update.impl_registers[CWND_REG];
        if (state->registers.impl_registers[CWND_REG] != 0) {
            conn->datapath->set_cwnd(conn, state->registers.impl_registers[CWND_REG]);
        }
    }

    if (state->pending_update.impl_is_pending[RATE_REG]) {
        libccp_debug("[sid=%d] Applying staged field update: rate reg <- " FMT_U64 "\n", conn->index, state->pending_update.impl_registers[RATE_REG]);
        state->registers.impl_registers[RATE_REG] = state->pending_update.impl_registers[RATE_REG];
        if (state->registers.impl_registers[RATE_REG] != 0) {
            conn->datapath->set_rate_abs(conn, state->registers.impl_registers[RATE_REG]);
        }
    }

    memset(&state->pending_update, 0, sizeof(struct staged_update));
    
    ret = state_machine(conn);
    if (!ret) {
        return ret;
    }

    return ret;
}

// lookup existing connection by its ccp socket id
// return NULL on error
struct ccp_connection *ccp_connection_lookup(struct ccp_datapath *datapath, u16 sid) {
    struct ccp_connection *conn;
    // bounds check
    if (sid == 0 || sid > datapath->max_connections) {
        libccp_warn("index out of bounds: %d", sid);
        return NULL;
    }

    conn = &datapath->ccp_active_connections[sid-1];
    if (conn->index != sid) {
        libccp_trace("index mismatch: sid %d, index %d", sid, conn->index);
        return NULL;
    }

    return conn;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(struct ccp_datapath *datapath, u16 sid) {
    int msg_size, ret;
    struct ccp_connection *conn;
    char msg[REPORT_MSG_SIZE];

    libccp_trace("Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > datapath->max_connections) {
        libccp_warn("index out of bounds: %d", sid);
        return;
    }

    conn = &datapath->ccp_active_connections[sid-1];
    if (conn->index != sid) {
        libccp_warn("index mismatch: sid %d, index %d", sid, conn->index);
        return;
    }

    free_ccp_priv_state(conn);

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, sid, 0, 0, 0);
    ret = datapath->send_msg(datapath, msg, msg_size);
    if (ret < 0) {
        if (!datapath->_in_fallback)  {
            libccp_warn("error sending close message: %d", ret);
        }
    }
    
    // ccp_connection_start will look for an array entry with index 0
    // to indicate that it's available for a new flow's information.
    // So, we set index to 0 here to reuse the memory.
    conn->index = 0;
    return;
}

// scan through datapath program table for the program with this UID
int datapath_program_lookup_uid(struct ccp_datapath *datapath, u32 program_uid) {
    size_t i;
    struct DatapathProgram *prog;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;
    
    for (i=0; i < datapath->max_programs; i++) {
        prog = &programs[i];
        if (prog->index == 0) {
            continue;
        }
        if (prog->program_uid == program_uid) {
            return (int)(prog->index);
        }
    }
    return LIBCCP_PROG_NOT_FOUND;
}

// saves a new datapath program into the array of datapath programs
// returns index into datapath program array where this program is stored
// if there is no more space, returns -1
int datapath_program_install(struct ccp_datapath *datapath, struct InstallExpressionMsgHdr* install_expr_msg, char* buf) {
    int i;
    int ret;
    u16 pid;
    char* msg_ptr; // for reading from char* buf
    struct InstructionMsg* current_instr;
    struct DatapathProgram* program;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;

    msg_ptr = buf;
    for (pid = 0; pid < datapath->max_programs; pid++) {
        program = &programs[pid];
        if (program->index == 0) {
            // found a free slot
            program->index = pid + 1;
            pid = pid + 1;
            break;
        }
    }
    if (pid >= datapath->max_programs) {
        libccp_warn("unable to install new program, table is full")
        return LIBCCP_PROG_TABLE_FULL;
    }

    // copy into the program
    program->index = pid;
    program->program_uid = install_expr_msg->program_uid;
    program->num_expressions = install_expr_msg->num_expressions;
    program->num_instructions = install_expr_msg->num_instructions;
    libccp_trace("Trying to install new program with (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    memcpy(program->expressions, msg_ptr, program->num_expressions * sizeof(struct ExpressionMsg));
    msg_ptr += program->num_expressions * sizeof(struct ExpressionMsg);

    // parse individual instructions
    for (i=0; i < (int)(program->num_instructions); i++) {
        current_instr = (struct InstructionMsg*)(msg_ptr);
        ret = read_instruction(&(program->fold_instructions[i]), current_instr);
        if (ret < 0) {
            libccp_warn("Could not read instruction # %d: %d in program with uid %u\n", i, ret, program->program_uid);
            return ret;
        }
        msg_ptr += sizeof(struct InstructionMsg);
    }

    libccp_debug("installed new program (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    return 0;

}

int stage_update(struct ccp_datapath *datapath __attribute__((unused)), struct staged_update *pending_update, struct UpdateField *update_field) {
    // update the value for these registers
    // for cwnd, rate; update field in datapath
    switch(update_field->reg_type) {
        case NONVOLATILE_CONTROL_REG:
        case VOLATILE_CONTROL_REG:
            // set new value
            libccp_trace(("%s: control " FMT_U32 " <- " FMT_U64 "\n"), __FUNCTION__, update_field->reg_index, update_field->new_value);
            pending_update->control_registers[update_field->reg_index] = update_field->new_value;
            pending_update->control_is_pending[update_field->reg_index] = true;
            return LIBCCP_OK;
        case IMPLICIT_REG:
            if (update_field->reg_index == CWND_REG) {
                libccp_trace("%s: cwnd <- " FMT_U64 "\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[CWND_REG] = update_field->new_value;
                pending_update->impl_is_pending[CWND_REG] = true;
            } else if (update_field->reg_index == RATE_REG) {
                libccp_trace("%s: rate <- " FMT_U64 "\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[RATE_REG] = update_field->new_value;
                pending_update->impl_is_pending[RATE_REG] = true;
            }
            return LIBCCP_OK;
        default:
            return LIBCCP_UPDATE_INVALID_REG_TYPE; // allowed only for CONTROL and CWND and RATE reg within CONTROL_REG
    }
}

int stage_multiple_updates(struct ccp_datapath *datapath, struct staged_update *pending_update, size_t num_updates, struct UpdateField *msg_ptr) {
    int ret;
    size_t i;
    for (i = 0; i < num_updates; i++) {
        ret = stage_update(datapath, pending_update, msg_ptr);
        if (ret < 0) {
            return ret;
        }

        msg_ptr++;
    }

    return LIBCCP_OK;
}

int ccp_read_msg(
    struct ccp_datapath *datapath,
    char *buf,
    int bufsize
) {
    int ret;
    int msg_program_index;
    u32 num_updates;
    char* msg_ptr;
    struct CcpMsgHeader hdr;
    struct ccp_connection *conn;
    struct ccp_priv_state *state;
    struct InstallExpressionMsgHdr expr_msg_info;
    struct ChangeProgMsg change_program;
    if (datapath->programs == NULL) {
        libccp_warn("datapath program state not initialized\n");
        return LIBCCP_PROG_IS_NULL;
    }

    ret = read_header(&hdr, buf);
    if (ret < 0) {
        libccp_warn("read header failed: %d", ret);
        return ret;
    }

    if (bufsize < 0) {
        libccp_warn("negative bufsize: %d", bufsize);
        return LIBCCP_BUFSIZE_NEGATIVE;
    }
    if (hdr.Len > ((u32) bufsize)) {
        libccp_warn("message size wrong: %u > %d\n", hdr.Len, bufsize);
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    if (hdr.Len > BIGGEST_MSG_SIZE) {
        libccp_warn("message too long: %u > %d\n", hdr.Len, BIGGEST_MSG_SIZE);
        return LIBCCP_MSG_TOO_LONG;
    }
    msg_ptr = buf + ret;


    _turn_off_fto_timer(datapath);

    // INSTALL_EXPR message is for all flows, not a specific connection
    // sock_id in this message should be disregarded (could be before any flows begin)
    if (hdr.Type == INSTALL_EXPR) {
        libccp_trace("Received install message\n");
        memset(&expr_msg_info, 0, sizeof(struct InstallExpressionMsgHdr));
        ret = read_install_expr_msg_hdr(datapath, &hdr, &expr_msg_info, msg_ptr);
        if (ret < 0) {
            libccp_warn("could not read install expression msg header: %d\n", ret);
            return ret;
        }
        // clear the datapath programs
        // TODO: implement a system for which each ccp process has an ID corresponding to its programs
        // as all programs are sent down separately, right now we check if its a new portus starting
        // by checking if the ID of the program is 0
        // TODO: remove this hack
        if (expr_msg_info.program_uid == 1) {
            memset(datapath->programs, 0, datapath->max_programs * sizeof(struct DatapathProgram));
        }

        msg_ptr += ret;
        ret = datapath_program_install(datapath, &expr_msg_info, msg_ptr);
        if ( ret < 0 ) {
            libccp_warn("could not install datapath program: %d\n", ret);
            return ret;
        }
        return LIBCCP_OK; // installed program successfully
    }

    // rest of the messages must be for a specific flow
    conn = ccp_connection_lookup(datapath, hdr.SocketId);
    if (conn == NULL) {
        libccp_trace("unknown connection: %u\n", hdr.SocketId);
        return LIBCCP_UNKNOWN_CONNECTION;
    }
    state = get_ccp_priv_state(conn);

    if (hdr.Type == UPDATE_FIELDS) {
        libccp_debug("[sid=%d] Received update_fields message\n", conn->index);
        ret = check_update_fields_msg(datapath, &hdr, &num_updates, msg_ptr);
        msg_ptr += ret;
        if (ret < 0) {
            libccp_warn("Update fields message failed: %d\n", ret);
            return ret;
        }

        ret = stage_multiple_updates(datapath, &state->pending_update, num_updates, (struct UpdateField*) msg_ptr);
        if (ret < 0) {
            libccp_warn("update_fields: failed to stage updates: %d\n", ret);
            return ret;
        }

        libccp_debug("Staged %u updates\n", num_updates);
    } else if (hdr.Type == CHANGE_PROG) {
        libccp_debug("[sid=%d] Received change_prog message\n", conn->index);
        // check if the program is in the program_table
        ret = read_change_prog_msg(datapath, &hdr, &change_program, msg_ptr);
        if (ret < 0) {
            libccp_warn("Change program message deserialization failed: %d\n", ret);
            return ret;
        }
        msg_ptr += ret;

        msg_program_index = datapath_program_lookup_uid(datapath, change_program.program_uid);
        if (msg_program_index < 0) {
            // TODO: is it possible there is not enough time between when the message is installed and when a flow asks to use the program?
            libccp_info("Could not find datapath program with program uid: %u\n", msg_program_index);
            return ret;
        }

        state->staged_program_index = (u16)msg_program_index; // index into program array for further lookup of instructions

        // clear any staged but not applied updates, as they are now irrelevant
        memset(&state->pending_update, 0, sizeof(struct staged_update));
        // stage any possible update fields to the initialized registers
        // corresponding to the new program
        ret = stage_multiple_updates(datapath, &state->pending_update, change_program.num_updates, (struct UpdateField*)(msg_ptr));
        if (ret < 0) {
            libccp_warn("change_prog: failed to stage updates: %d\n", ret);
            return ret;
        }

        libccp_debug("Staged switch to program %d\n", change_program.program_uid);
    }

    return ret;
}

// send create msg
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
) {
    int ret;
    char msg[CREATE_MSG_SIZE];
    int msg_size;
    struct CreateMsg cr = {
        .init_cwnd = conn->flow_info.init_cwnd,
        .mss = conn->flow_info.mss,
        .src_ip = conn->flow_info.src_ip,
        .src_port = conn->flow_info.src_port,
        .dst_ip = conn->flow_info.dst_ip,
        .dst_port = conn->flow_info.dst_port,
    };
    memcpy(&cr.congAlg, &conn->flow_info.congAlg, MAX_CONG_ALG_SIZE);

    if (
        conn->last_create_msg_sent != 0 &&
        datapath->since_usecs(conn->last_create_msg_sent) < CREATE_TIMEOUT_US
    ) {
        libccp_trace("%s: " FMT_U64 " < " FMT_U32 "\n", 
            __FUNCTION__, 
            datapath->since_usecs(conn->last_create_msg_sent), 
            CREATE_TIMEOUT_US
        );
        return LIBCCP_CREATE_PENDING;
    }

    if (conn->index < 1) {
        return LIBCCP_CONNECTION_NOT_INITIALIZED;
    }

    conn->last_create_msg_sent = datapath->now();
    msg_size = write_create_msg(msg, CREATE_MSG_SIZE, conn->index, cr);
    if (msg_size < 0) {
        return msg_size;
    }

    ret = datapath->send_msg(datapath, msg, msg_size);
    if (ret) {
        libccp_debug("error sending create, updating fto_timer")
        _update_fto_timer(datapath);
    }
    return ret;
}

void _update_fto_timer(struct ccp_datapath *datapath) {
    if (!datapath->last_msg_sent) {
        datapath->last_msg_sent = datapath->now();
    }
}

/*
 * Returns true if CCP has timed out, false otherwise
 */
bool _check_fto(struct ccp_datapath *datapath) {
    // TODO not sure how well this will scale with many connections,
    //      may be better to make it per conn
    u64 since_last = datapath->since_usecs(datapath->last_msg_sent);
    bool should_be_in_fallback = datapath->last_msg_sent && (since_last > datapath->fto_us);

    if (should_be_in_fallback && !datapath->_in_fallback) {
        datapath->_in_fallback = true;
        libccp_error("ccp fallback (%lu since last msg)\n", since_last);
    } else if (!should_be_in_fallback && datapath->_in_fallback) {
        datapath->_in_fallback = false;
        libccp_error("ccp should not be in fallback");
    }
    return should_be_in_fallback;
}

void _turn_off_fto_timer(struct ccp_datapath *datapath) {
    if (datapath->_in_fallback) {
        libccp_error("ccp restored!\n");
    }
    datapath->_in_fallback = false;
    datapath->last_msg_sent = 0;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
) {
    int ret;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    struct ccp_datapath *datapath __attribute__((unused)) = conn->datapath;

    if (conn->index < 1) {
        return LIBCCP_CONNECTION_NOT_INITIALIZED;
    }

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, program_uid, fields, num_fields);
    libccp_trace("[sid=%d] In %s\n", conn->index, __FUNCTION__);
    ret = conn->datapath->send_msg(datapath, msg, msg_size);
    if(ret) {
        libccp_debug("error sending measurement, updating fto timer");
        _update_fto_timer(datapath);
    }
    return ret;
}

/********************************end*********************************/
/*******************************ccp.c********************************/
/********************************************************************/

#define MAX_SKB_STORED 50

#define MAX_ACTIVE_FLOWS 1024
#define MAX_DATAPATH_PROGRAMS 10

struct skb_info {
    u64 first_tx_mstamp; // choose the correct skb so the timestamp for first packet
    u32 interval_us; // interval us as calculated from this SKB
};

struct ccp {
    // control
    u32 last_snd_una; // 4 B
    u32 last_bytes_acked; // 8 B
    u32 last_sacked_out; // 12 B
    struct skb_info *skb_array; // array of future skb information

    // communication
    struct ccp_connection *conn;
};

#define MTU 1500
#define S_TO_US 1000000

void ccp_set_pacing_rate(struct sock *sk, uint32_t rate);
/********************************end*********************************/
/************************#include "tcp_ccp.h"************************/
/********************************************************************/
//#include "libccp/ccp.h"
//#include "libccp/ccp_error.h"

#if __KERNEL_VERSION_MINOR__ <= 14 && __KERNEL_VERSION_MINOR__ >= 13
#define COMPAT_MODE
#elif __KERNEL_VERSION_MAJOR__ > 4
#define RATESAMPLE_MODE
#elif __KERNEL_VERSION_MAJOR__ == 4 && __KERNEL_VERSION_MINOR__ >= 19
#define RATESAMPLE_MODE
#endif

#define IPC_NETLINK 0
#define IPC_CHARDEV 1

#if __IPC__ == IPC_NETLINK
/********************************************************************/
/************************#include "ccp_nl.h"*************************/
/*******************************begin********************************/
//#include "libccp/ccp.h"

typedef int (*ccp_nl_recv_handler)(struct ccp_datapath *datapath, char *msg, int msg_size);

/* Create a netlink kernel socket
 * A global (struct sock*), ccp_nl_sk, will get set so we can use the socket
 * There is *only one* netlink socket active *per datapath*
 */
int ccp_nl_sk(ccp_nl_recv_handler msg);

/* Wrap netlink_kernel_release of (struct sock *ccp_nl_sk).
 */
void free_ccp_nl_sk(void);

/* Send serialized message to userspace CCP
 */
int nl_sendmsg(
    struct ccp_datapath *dp,
    char *msg, 
    int msg_size
);
/********************************end*********************************/
/************************#include "ccp_nl.h"*************************/
/********************************************************************/

/********************************************************************/
/******************************ccp_nl.c******************************/
/*******************************begin********************************/
#include <net/tcp.h>
//#include "ccp_nl.h"

#define CCP_MULTICAST_GROUP 22

ccp_nl_recv_handler ccp_msg_reader = NULL;
struct sock *nl_sk;
extern struct ccp_datapath *kernel_datapath;

// callback from userspace ccp
// all messages will be PatternMsg OR InstallFoldMsg
// lookup ccp socket id, install new pattern
void nl_recv(struct sk_buff *skb) {
    int ok;
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    if (ccp_msg_reader == NULL) {
        pr_info("[ccp] [nl] ccp_msg_reader not ready\n");
        return;
    }
    
    //printk(KERN_INFO "[ ");
    //for (i = 0; i < hdr->Len; i++) {
    //    printk(KERN_INFO "%02x, ", (u32) buf[i]);
    //}
    //printk(KERN_INFO "]\n");

    ok = ccp_msg_reader(kernel_datapath, (char*)nlmsg_data(nlh), nlh->nlmsg_len);
    if (ok < 0) {
        pr_info("[ccp] [nl] message read failed: %d.\n", ok);
    }
}

int ccp_nl_sk(ccp_nl_recv_handler msg) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv,
    };

    ccp_msg_reader = msg;
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "[ccp] [nl] Error creating netlink socket.\n");
        return -1;
    }

    return 0;
}

void free_ccp_nl_sk(void) {
    netlink_kernel_release(nl_sk);
}

// send IPC message to userspace ccp
int nl_sendmsg(
    struct ccp_datapath *dp,
    char *msg, 
    int msg_size
) {
    int res;
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;

    //pr_info("ccp: sending nl message: (%d) type: %02x len: %02x sid: %04x", msg_size, *msg, *(msg + sizeof(u8)), *(msg + 2*sizeof(u8)));

    skb_out = nlmsg_new(
        msg_size,  // @payload: size of the message payload
        GFP_NOWAIT // @flags: the type of memory to allocate.
    );
    if (!skb_out) {
        printk(KERN_ERR "[ccp] [nl] Failed to allocate new skb\n");
        return -1;
    }

    nlh = nlmsg_put(
        skb_out,    // @skb: socket buffer to store message in
        0,          // @portid: netlink PORTID of requesting application
        0,          // @seq: sequence number of message
        NLMSG_DONE, // @type: message type
        msg_size,   // @payload: length of message payload
        0           // @flags: message flags
    );

    memcpy(nlmsg_data(nlh), msg, msg_size);
    // https://www.spinics.net/lists/netdev/msg435978.html
    // "It is process context but with a spinlock (bh_lock_sock) held, so
    // you still can't sleep. IOW, you have to pass a proper gfp flag to
    // reflect this."
    // Use an allocation without __GFP_DIRECT_RECLAIM
    res = nlmsg_multicast(
        nl_sk,               // @sk: netlink socket to spread messages to
        skb_out,             // @skb: netlink message as socket buffer
        0,                   // @portid: own netlink portid to avoid sending to yourself
        CCP_MULTICAST_GROUP, // @group: multicast group id
        GFP_NOWAIT           // @flags: allocation flags
    );
    if (res < 0) {
        return res;
    }

    return 0;
}
/********************************end*********************************/
/******************************ccp_nl.c******************************/
/********************************************************************/

#elif __IPC__ == IPC_CHARDEV
/********************************************************************/
/**********************#include "ccpkp/ccpkp.h"**********************/
/*******************************begin********************************/
#include <linux/slab.h>
#include <linux/cdev.h>
/********************************************************************/
/************************#include "lfq/lfq.h"************************/
/*******************************begin********************************/
#ifdef __KERNEL__
    #include <linux/slab.h>
    #include <linux/sched.h>
    #include <linux/wait.h>
    #include <linux/uaccess.h>

    #ifndef __MALLOC__
            #define __MALLOC__(size) kmalloc(size, GFP_KERNEL)
    #endif
    #ifndef ___FREE___
            #define ___FREE___(p)      kfree(p)
    #endif
    #define CAS(a,o,n)       cmpxchg(a,o,n) == o
    #define ASSERT(cond)
    #ifndef COPY_TO_USER
            #define COPY_TO_USER(dst, src, n) copy_to_user(dst, src, n)
    #endif
    #ifndef COPY_FROM_USER
            #define COPY_FROM_USER(dst, src, n) copy_from_user(dst, src, n)
    #endif
#else
    #include <stdbool.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>
    #include <stdint.h>
    #include <errno.h>
    #include <assert.h>
    #include <pthread.h>

    #ifndef __MALLOC__
        #define __MALLOC__(size) malloc(size)
    #endif
    #ifndef ___FREE___
        #define ___FREE___(p)      free(p)
    #endif
    #define CAS(a,o,n)       __sync_bool_compare_and_swap(a,o,n)
    #define ASSERT(cond) assert(cond)
    #ifndef COPY_TO_USER
            #define COPY_TO_USER(dst, src, n) memcpy(dst, src, n)
    #endif
    #ifndef COPY_FROM_USER
            #define COPY_FROM_USER(dst, src, n) memcpy(dst, src, n)
    #endif
#endif


#ifdef __DEBUG__
    #ifdef __KERNEL__
         /* This one if debugging is on, and kernel space */
        #define PDEBUG(fmt, args...) printk( KERN_DEBUG "ccp-kpipe: " fmt, ## args)
    #else
        /* This one for user space */
        #define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
    #endif
#else
    /* Debugging off */
    #define PDEBUG(fmt, args...) 
#endif

#ifndef max
#define max(a,b) \
 ({ __typeof__ (a) _a = (a); \
         __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#define min(a,b) \
 ({ __typeof__ (a) _a = (a); \
         __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

#define idx_t uint16_t 
#define KERNELSPACE 0
#define USERSPACE 1

// Must be a divisor of max val of id_t
#define BACKLOG 1024
#define MAX_MSG_LEN 512
#define BUF_LEN (BACKLOG*MAX_MSG_LEN)

struct lfq {
    char *buf;
    char **msg_list;
    char **free_list;

    idx_t read_head, write_head;
    idx_t free_head, free_tail;

    bool blocking;
#ifdef __KERNEL__
    wait_queue_head_t nonempty;
#else
    pthread_cond_t nonempty;
    pthread_mutex_t wait_lock;
#endif
};

struct pipe {
    struct lfq ccp_write_queue;
    struct lfq dp_write_queue;
};

int init_lfq(struct lfq *q, bool blocking);
void free_lfq(struct lfq *q);
void init_pipe(struct pipe *p, bool blocking);
void free_pipe(struct pipe *p);

char* _lfq_acquire_free_block(struct lfq *q);
void _lfq_return_block(struct lfq *q, char *block);
uint16_t read_portus_msg_size(char *buf);

ssize_t lfq_read(struct lfq *q, char *buf, size_t bytes_to_read, int reader_t);
ssize_t lfq_write(struct lfq *q, const char *buf, size_t bytes_to_write, int id, int writer_t);
ssize_t ccp_write(struct pipe *p, const char *buf, size_t bytes_to_write, int id);
ssize_t ccp_read(struct pipe *p, char *buf, size_t bytes_to_read);
ssize_t dp_write(struct pipe *p, const char *buf, size_t bytes_to_write, int id);
ssize_t dp_read(struct pipe *p, char *buf, size_t bytes_to_read);
/********************************end*********************************/
/************************#include "lfq/lfq.h"************************/
/********************************************************************/

/********************************************************************/
/*******************************lfq.c********************************/
/*******************************begin********************************/
//#include "lfq.h"

void debug_buf(const char *buf) {
	char out[256];
	char *tmp = out;
        int wrote = sprintf(tmp, "buf=%p\n", buf); 
        tmp += wrote;
	for(int i=0; i<64; i++) {
		sprintf(tmp, "|%2d", i);
		tmp += 3;
	}
	sprintf(tmp, "|\n");
	printk( KERN_DEBUG "%s", out);
	tmp = out;
	for(int i=0; i<64; i++) {
		sprintf(tmp, "|%02x", buf[i]);
		tmp += 3;
	}
	sprintf(tmp, "|\n");
	printk( KERN_DEBUG "%s", out);
}

int init_lfq(struct lfq *q, bool blocking) {
    q->buf       = __MALLOC__(BUF_LEN);
    if (!q->buf) {
        return -1;
    }
    q->msg_list  = __MALLOC__(BACKLOG * sizeof(char *));
    if (!q->msg_list) {
        ___FREE___(q->buf);
        return -1;
    }
    q->free_list = __MALLOC__(BACKLOG * sizeof(char *));
    if (!q->free_list) {
        ___FREE___(q->buf);
        ___FREE___(q->msg_list);
        return -1;
    }

    for (int i=0; i<BACKLOG; i++) {
        q->free_list[i] = &(q->buf[i * MAX_MSG_LEN]);
        q->msg_list[i] = NULL;
    }

    q->read_head  = 
    q->write_head = 
    q->free_head  = 0;
    q->free_tail  = BACKLOG-1;

    q->blocking = blocking;
    if (blocking) {
#ifdef __KERNEL__
        init_waitqueue_head(&q->nonempty);
#else
        pthread_mutex_init(&q->wait_lock, NULL);
        pthread_cond_init(&q->nonempty, NULL);
#endif
    }

    return 0;
}

void free_lfq(struct lfq *q) {
    ___FREE___(q->buf);
    ___FREE___(q->msg_list);
    ___FREE___(q->free_list);
}

void init_pipe(struct pipe *p, bool blocking) {
    init_lfq(&p->ccp_write_queue, blocking);
    init_lfq(&p->dp_write_queue, blocking);
}

void free_pipe(struct pipe *p) {
    free_lfq(&p->ccp_write_queue);
    free_lfq(&p->dp_write_queue);
    ___FREE___(p);
}

char* _lfq_acquire_free_block(struct lfq *q) {
    idx_t head, new_head;
    for (;;) {
        head = q->free_head;
        new_head = (head+1) % BACKLOG;
        if (new_head == q->free_tail) {
            return NULL; // Free list is (technically, almost) empty
        }
        if (CAS(&(q->free_head), head, new_head)) {
            break;
        }
    }

    if(new_head == 0) {
        new_head = BACKLOG;
    }

    return q->free_list[new_head-1];
}

void _lfq_return_block(struct lfq *q, char *block) {
    idx_t tail, new_tail;
    for (;;) {
        tail = q->free_tail;
        new_tail = (tail+1) % BACKLOG;
        //ASSERT(new_tail <= q->free_head);
        if (CAS(&(q->free_tail), tail, new_tail)) {
            break;
        }
    }

    if(new_tail == 0) {
        new_tail = BACKLOG;
    }

    PDEBUG("[reader  ] returned block to %d\n", new_tail);

    q->free_list[new_tail - 1] = block;
}

uint16_t read_portus_msg_size(char *buf) {
    return *(((uint16_t *)buf)+1);
}

inline bool ready_for_reading(struct lfq *q) {
    return (q->read_head != q->write_head) && (q->msg_list[q->read_head] != NULL);
}

ssize_t lfq_read(struct lfq *q, char *buf, size_t bytes_to_read, int reader_t) {

    if (q->blocking) {
wait_until_nonempty:
#ifndef __KERNEL__
        pthread_mutex_lock(&q->wait_lock);
#endif
        while (!ready_for_reading(q)) {
#ifdef __KERNEL__
            if (wait_event_interruptible(q->nonempty, ready_for_reading(q))) {
                return -ERESTARTSYS;
            }
#else
            pthread_cond_wait(&q->nonempty, &q->wait_lock);
#endif
        }
#ifndef __KERNEL__
        pthread_mutex_unlock(&q->wait_lock);
#endif
    } else {
        if (!ready_for_reading(q)) {
            return 0;
        }
    }

    int bytes_read = 0;

    PDEBUG("[reader  ] read=%d write=%d\n", q->read_head, q->write_head);

    idx_t old_r, new_r;
    int count = 1;
    for (;;) {
        old_r = new_r = q->read_head;
        int bytes_can_read = bytes_to_read;
        uint16_t bytes_in_block;
        while (bytes_can_read > 0) {
            if (q->msg_list[new_r] == NULL) {
                break;
            }
            bytes_in_block = read_portus_msg_size(q->msg_list[new_r]);
            bytes_can_read -= bytes_in_block;
            new_r = (new_r + 1) % BACKLOG;
            if (new_r == q->write_head) {
                 break;
            }
        }
        //PDEBUG("[reader  ] trying to move read from %d to %d\n", old_r, new_r);
        if (CAS(&(q->read_head), old_r, new_r)) {
            //PDEBUG("[reader  ] moved\n");
            break;
        }
        count++;
    }
    if (new_r < old_r) { // wrapped
        new_r += BACKLOG;
    }
    PDEBUG("reading from %d to %d\n", old_r, new_r);
    for (int i=old_r; i < new_r; i++) {
        int r = i % BACKLOG;
        char *block = q->msg_list[r];
        uint16_t bytes_in_block = read_portus_msg_size(block);
        PDEBUG("[reader  ] read #%d (@%ld) : %d bytes\n", r, block-q->buf, bytes_in_block);
        if (reader_t == USERSPACE) {
            COPY_TO_USER(buf, block, bytes_in_block);
        } else { // reader_t == KERNELSPACE
            memcpy(buf, block, bytes_in_block);
        }
        bytes_read += bytes_in_block;
        _lfq_return_block(q, block);
        q->msg_list[r] = NULL;
        buf += bytes_in_block;
    }
    
    if (bytes_read == 0) {
        goto wait_until_nonempty;
    }

    return bytes_read;
}


ssize_t lfq_write(struct lfq *q, const char *buf, size_t bytes_to_write, int id, int writer_t) {
    // Get free block
    char *block = _lfq_acquire_free_block(q);
    if (block == NULL) {
        PDEBUG("[writer %d] no free blocks available\n", id);
        return -1;
    }
    PDEBUG("[writer %d] acquired free block at %ld (head=%d, tail=%d)\n", id, block - q->buf, q->free_head, q->free_tail);

    // Copy data into block
    if (writer_t == USERSPACE) {
        COPY_FROM_USER(block, buf, bytes_to_write);
    } else { // writer_t == KERNELSPACE
        memcpy(block, buf, bytes_to_write);
    }

    // Get next position in queue
    idx_t old_i, new_i;
    int count = 1;
    for (;;) {
        old_i = q->write_head;
        new_i = (old_i + 1) % BACKLOG;
        if (new_i == q->read_head) {
            return 0; // TODO what do we want to do if there's no room?
        }
        if (CAS(&(q->write_head), old_i, new_i)) {
            break;
        }
        count++;
    }

    if (new_i == 0) {
        new_i = BACKLOG;
    }
    PDEBUG("[writer %d] secured queue #%d : %ld bytes\n", id, (new_i-1), bytes_to_write);

    // Assign block to acquired position
    q->msg_list[new_i-1] = block;

    if (q->blocking) {
#ifdef __KERNEL__
        wake_up_interruptible(&q->nonempty);
#else
        pthread_mutex_lock(&q->wait_lock);
        pthread_cond_signal(&q->nonempty);
        pthread_mutex_unlock(&q->wait_lock);
#endif
    }

    return bytes_to_write;
}

ssize_t ccp_write(struct pipe *p, const char *buf, size_t bytes_to_write, int id) {
    return lfq_write(&p->ccp_write_queue, buf, bytes_to_write, id, USERSPACE);
}
ssize_t ccp_read(struct pipe *p, char *buf, size_t bytes_to_read) {
    return lfq_read(&p->dp_write_queue, buf, bytes_to_read, USERSPACE);
}
ssize_t dp_write(struct pipe *p, const char *buf, size_t bytes_to_write, int id) {
    return lfq_write(&p->dp_write_queue, buf, bytes_to_write, id, KERNELSPACE);
}
ssize_t dp_read(struct pipe *p, char *buf, size_t bytes_to_read) {
    return lfq_read(&p->ccp_write_queue, buf, bytes_to_read, KERNELSPACE);
}
/********************************end*********************************/
/*******************************lfq.c********************************/
/********************************************************************/

//#include "../libccp/ccp.h"

#ifndef MAX_CCPS
#define MAX_CCPS 32
#endif

typedef int (*ccp_recv_handler)(char *msg, int msg_size);

struct kpipe {
    int    ccp_id;              /* Index of this pipe in pipes */
    struct lfq ccp_write_queue; /* Queue from user to kernel  */
    struct lfq dp_write_queue;  /* Queue from kernel to user  */
};

struct ccpkp_dev {
    int    num_ccps;
    struct kpipe *pipes[MAX_CCPS];
    struct cdev cdev;
    struct mutex mux;
};

int         ccpkp_init(ccp_recv_handler handler);
int         ccpkp_user_open(struct inode *, struct file *);
ssize_t     ccpkp_user_read(struct file *fp, char *buf, size_t bytes_to_read, loff_t *offset);
void        ccpkp_try_read(void);
ssize_t     ccpkp_kernel_read(struct kpipe *pipe, char *buf, size_t bytes_to_read);
ssize_t     ccpkp_user_write(struct file *fp, const char *buf, size_t bytes_to_write, loff_t *offset);
int         ccpkp_sendmsg(struct ccp_connection *conn, char *buf, int bytes_to_write);
ssize_t     ccpkp_kernel_write(struct kpipe *pipe, const char *buf, size_t bytes_to_read, int id);
int         ccpkp_user_release(struct inode *, struct file *);
void        ccpkp_cleanup(void);
/********************************end*********************************/
/**********************#include "ccpkp/ccpkp.h"**********************/
/********************************************************************/

/********************************************************************/
/******************************ccpkp.c*******************************/
/*******************************begin********************************/
/*
 * Character device for IPC between user-space and kernel-space CCP proccesses
 *
 * Frank Cangialosi <frankc@csail.mit.edu>
 * Created: April, 2018
 * Version 2
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/atomic.h>

#include <asm/uaccess.h>

//#include "ccpkp.h"

#define DEV_NAME "ccpkp"

struct ccpkp_dev *ccpkp_dev;
int ccpkp_major;

// NOTE: hack for now since there's only one ccp.
//       if we want to support multiple ccps, datapath
//       will need a way to differentiate between them
int curr_ccp_id; 

ccp_recv_handler libccp_read_msg;
#define RECVBUF_LEN 4096
char recvbuf[RECVBUF_LEN];

static struct file_operations ccpkp_fops = 
{
    .owner    = THIS_MODULE,
    .open     = ccpkp_user_open,
    .read     = ccpkp_user_read,
    .write    = ccpkp_user_write,
    .release  = ccpkp_user_release
};

int ccpkp_init(ccp_recv_handler handler) {
    int result, err;
    int devno;
    dev_t dev = 0;

    libccp_read_msg = handler;

    result = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
    ccpkp_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "ccp-kpipe: failed to register\n");
        return result;
    }

    ccpkp_dev = kmalloc(1 * sizeof(struct ccpkp_dev), GFP_KERNEL);
    if (!ccpkp_dev) {
        result = -ENOMEM;
        goto fail;
    }
    memset(ccpkp_dev, 0, 1 * sizeof(struct ccpkp_dev));
    
    mutex_init(&(ccpkp_dev->mux));
    devno = MKDEV(ccpkp_major, 0);
    cdev_init(&ccpkp_dev->cdev, &ccpkp_fops);
    ccpkp_dev->cdev.owner = THIS_MODULE;
    ccpkp_dev->cdev.ops = &ccpkp_fops;
    err = cdev_add(&ccpkp_dev->cdev, devno, 1);
    if (err) {
        printk(KERN_NOTICE "ccp-kpipe: error %d adding cdev\n", err);
    }
    
    printk(KERN_INFO "ccp-kpipe: device (%d) created successfully\n", ccpkp_major);


    return 0;

fail:
    ccpkp_cleanup();
    return result;
}

void ccpkp_cleanup(void) {
    dev_t devno = MKDEV(ccpkp_major, 0);

    if (ccpkp_dev) {
        // TODO free all queue buffers
        cdev_del(&ccpkp_dev->cdev);
        kfree(ccpkp_dev);
    }
    unregister_chrdev_region(devno, 1);
    ccpkp_dev = NULL;

    printk(KERN_INFO "ccp-kpipe: goodbye\n");
}

int ccpkp_user_open(struct inode *inp, struct file *fp) {
    // Create new pipe for this CCP
    struct kpipe *pipe = kmalloc(sizeof(struct kpipe), GFP_KERNEL);
    int i, ccp_id; 
#ifndef ONE_PIPE
    bool user_read_nonblock = fp->f_flags & O_NONBLOCK;
#endif

    memset(pipe, 0, sizeof(struct kpipe));
    if (!pipe) {
        return -ENOMEM;
    }

    PDEBUG("init lfq");
    if (init_lfq(&pipe->ccp_write_queue, false) < 0) {
        return -ENOMEM;
    }
#ifndef ONE_PIPE
    PDEBUG("init lfq");
    if (init_lfq(&pipe->dp_write_queue, !user_read_nonblock) < 0) {
        return -ENOMEM;
    }
#endif
    
    // Store pointer to pipe in struct file
    fp->private_data = pipe;

    if (mutex_lock_interruptible(&ccpkp_dev->mux)) {
        // We were interrupted (e.g. by a signal),
        // Let the kernel figure out what to do, maybe restart syscall
        return -ERESTARTSYS;
    }
    // TODO this gets decremented later, need to get last allocated instead
    PDEBUG("got lock, getting id");
    ccp_id = ccpkp_dev->num_ccps;
    if (ccp_id >= MAX_CCPS) {
        ccp_id = -1;
        for (i = 0; i < MAX_CCPS; i++) {
            if (ccpkp_dev->pipes[i] == NULL) {
                ccp_id = i;
                break;
            }
        }
        if (ccp_id == -1) {
            printk(KERN_WARNING "ccp-kpipe: max ccps registered\n");
            return -ENOMEM;
        }
    }
    ccpkp_dev->pipes[ccp_id] = pipe;
    pipe->ccp_id = ccp_id;
    ccpkp_dev->num_ccps++;
    mutex_unlock(&ccpkp_dev->mux);
    PDEBUG("init done");

    return 0;
}

void kpipe_cleanup(struct kpipe *pipe) {
    free_lfq(&pipe->ccp_write_queue);
    #ifndef ONE_PIPE
    free_lfq(&pipe->dp_write_queue);
    #endif
    kfree(pipe);
}

int ccpkp_user_release(struct inode *inp, struct file *fp) {
    struct kpipe *pipe = fp->private_data;
    int ccp_id = pipe->ccp_id;

    if (mutex_lock_interruptible(&ccpkp_dev->mux)) {
        return -ERESTARTSYS;
    }
    ccpkp_dev->pipes[pipe->ccp_id] = NULL;
    ccpkp_dev->num_ccps--;
    mutex_unlock(&ccpkp_dev->mux);
    
    kpipe_cleanup(pipe);
    fp->private_data = NULL;

    printk(KERN_INFO "ccp-kpipe: ccp %d closed\n", ccp_id);
    return 0;
}

ssize_t ccpkp_user_read(struct file *fp, char *buf, size_t bytes_to_read, loff_t *offset) {
    struct kpipe *pipe = fp->private_data;
#ifdef ONE_PIPE
    struct lfq *q = &(pipe->ccp_write_queue);
#else
    struct lfq *q = &(pipe->dp_write_queue);
#endif
    PDEBUG("user wants to read %lu bytes", bytes_to_read);
    return lfq_read(q, buf, bytes_to_read, USERSPACE);
}

// module stores pointer to corresponding ccp kpipe for each socket
ssize_t ccpkp_kernel_read(struct kpipe *pipe, char *buf, size_t bytes_to_read) {
#ifdef ONE_PIPE
    printk("error: compiled with a single pipe for test purposes. recompile with ONE_PIPE=n\n");
    return 0;
#endif
    struct lfq *q = &(pipe->ccp_write_queue);
    PDEBUG("kernel wants to read %lu bytes", bytes_to_read);
    return lfq_read(q, buf, bytes_to_read, KERNELSPACE);
}

ssize_t ccpkp_user_write(struct file *fp, const char *buf, size_t bytes_to_write, loff_t *offset) {
    struct kpipe *pipe = fp->private_data;
    struct lfq *q = &(pipe->ccp_write_queue);
    PDEBUG("user wants to write %lu bytes", bytes_to_write);
    return lfq_write(q, buf, bytes_to_write, 0, USERSPACE);
}


// module stores pointer to corresponding ccp kpipe for each socket
ssize_t ccpkp_kernel_write(struct kpipe *pipe, const char *buf, size_t bytes_to_write, int id) {
#ifdef ONE_PIPE
    printk("error: compiled with a single pipe for test purposes. recompile with ONE_PIPE=n\n");
    return 0;
#endif
    struct lfq *q = &(pipe->dp_write_queue);
    PDEBUG("kernel wants to write %lu bytes", bytes_to_write);
    return lfq_write(q, buf, bytes_to_write, id, KERNELSPACE);
}



void ccpkp_try_read(void) {
    ssize_t bytes_read;
    bytes_read = ccpkp_kernel_read(ccpkp_dev->pipes[curr_ccp_id], recvbuf, RECVBUF_LEN);
    if (bytes_read > 0) {
        PDEBUG("kernel read %ld bytes", bytes_read);
        libccp_read_msg(recvbuf, bytes_read);
    }
}

int ccpkp_sendmsg(
        struct ccp_connection *conn,
        char *buf,
        int bytes_to_write
) {
    if (bytes_to_write < 0) {
        return -1;
    }
    PDEBUG("kernel->user trying to write %d bytes", bytes_to_write);
    return ccpkp_kernel_write(ccpkp_dev->pipes[curr_ccp_id], buf, (size_t) bytes_to_write, (int) conn->index+1);
}
/********************************end*********************************/
/******************************ccpkp.c*******************************/
/********************************************************************/

#endif

#include <linux/module.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <net/tcp.h>

#define CCP_FRAC_DENOM 10
#define CCP_EWMA_RECENCY 6

// Global internal state -- allocated during ccp_init and freed in ccp_free.
struct ccp_datapath *kernel_datapath;

void ccp_set_pacing_rate(struct sock *sk, uint32_t rate) {
    sk->sk_pacing_rate = rate;
}

static int rate_sample_valid(const struct rate_sample *rs) {
  int ret = 0;
  if (rs->delivered <= 0)
    ret |= 1;
  if (rs->interval_us <= 0)
    ret |= 1 << 1;
  if (rs->rtt_us <= 0)
    ret |= 1 << 2;
  return ret;
}

static inline void get_sock_from_ccp(
    struct sock **sk,
    struct ccp_connection *conn
) {
    *sk = (struct sock*) ccp_get_impl(conn);
}

static void do_set_cwnd(
    struct ccp_connection *conn, 
    uint32_t cwnd
) {
    struct sock *sk;
    struct tcp_sock *tp;
    get_sock_from_ccp(&sk, conn);
    tp = tcp_sk(sk);

    // translate cwnd value back into packets
    cwnd /= tp->mss_cache;
    tp->snd_cwnd = cwnd;
}

static void do_set_rate_abs(
    struct ccp_connection *conn, 
    uint32_t rate
) {
    struct sock *sk;
    get_sock_from_ccp(&sk, conn);
    ccp_set_pacing_rate(sk, rate);
}

struct timespec64 tzero;
static u64 ccp_now(void) {
    struct timespec64 now, diff;
    ktime_get_real_ts64(&now);
    diff = timespec64_sub(now, tzero);
    return timespec64_to_ns(&diff);
}

static u64 ccp_since(u64 then) {
    struct timespec64 now, then_ts, diff;
    ktime_get_real_ts64(&now);
    then_ts = tzero;
    timespec64_add_ns(&then_ts, then);
    diff = timespec64_sub(now, then_ts);
    return timespec64_to_ns(&diff) / NSEC_PER_USEC;
}

static u64 ccp_after(u64 us) {
    struct timespec64 now;
    ktime_get_real_ts64(&now);
    now = timespec64_sub(now, tzero);
    timespec64_add_ns(&now, us * NSEC_PER_USEC);
    return timespec64_to_ns(&now);
}

// in dctcp code, in ack event used for ecn information per packet
void tcp_ccp_in_ack_event(struct sock *sk, u32 flags) {
    // according to tcp_input, in_ack_event is called before cong_control, so mmt.ack has old ack value
    const struct tcp_sock *tp = tcp_sk(sk);
    struct ccp *ca = inet_csk_ca(sk);
    struct ccp_primitives *mmt;
    u32 acked_bytes;
#ifdef COMPAT_MODE
    int i=0;
    struct sk_buff *skb = tcp_write_queue_head(sk);
    struct tcp_skb_cb *scb;
#endif

    if (ca->conn == NULL) {
        pr_info("[ccp] ccp_connection not initialized");
        return;
    }

#ifdef COMPAT_MODE
    for (i=0; i < MAX_SKB_STORED; i++) {
        ca->skb_array[i].first_tx_mstamp = 0;
        ca->skb_array[i].interval_us = 0;
    }

    for (i=0; i < MAX_SKB_STORED; i++) {
        if (skb) {
            scb = TCP_SKB_CB(skb);
            ca->skb_array[i].first_tx_mstamp = skb->skb_mstamp;
            ca->skb_array[i].interval_us = tcp_stamp_us_delta(skb->skb_mstamp, scb->tx.first_tx_mstamp);
            skb = skb->next;
        }
    }
#endif
    
    mmt = &ca->conn->prims;
    acked_bytes = tp->snd_una - ca->last_snd_una;
    ca->last_snd_una = tp->snd_una;
    if (acked_bytes) {
        if (flags & CA_ACK_ECE) {
            mmt->ecn_bytes = (u64)acked_bytes;
            mmt->ecn_packets = (u64)acked_bytes / tp->mss_cache;
        } else {
            mmt->ecn_bytes = 0;
            mmt->ecn_packets = 0;
        }
    }
}
EXPORT_SYMBOL_GPL(tcp_ccp_in_ack_event);

/* load the primitive registers of the rate sample - convert all to u64
 * raw values, not averaged
 */
int load_primitives(struct sock *sk, const struct rate_sample *rs) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccp *ca = inet_csk_ca(sk);
    struct ccp_primitives *mmt = &ca->conn->prims;
#ifdef COMPAT_MODE
    int i=0;
#endif

    u64 rin = 0; // send bandwidth in bytes per second
    u64 rout = 0; // recv bandwidth in bytes per second
    u64 ack_us = 0;
    u64 snd_us = 0;
    int measured_valid_rate = rate_sample_valid(rs);
    if ( measured_valid_rate != 0 ) {
        return -1;
    }

#ifdef COMPAT_MODE
    // receive rate
    ack_us = tcp_stamp_us_delta(tp->tcp_mstamp, rs->prior_mstamp);

    // send rate
    for (i=0; i < MAX_SKB_STORED; i++) {
        if (ca->skb_array[i].first_tx_mstamp == tp->first_tx_mstamp) {
            snd_us = ca->skb_array[i].interval_us;
            break;
        }
    }
#endif
#ifdef RATESAMPLE_MODE
    ack_us = rs->rcv_interval_us;
    snd_us = rs->snd_interval_us;
#endif

    if (ack_us != 0 && snd_us != 0) {
        rin = rout = (u64)rs->delivered * MTU * S_TO_US;
        do_div(rin, snd_us);
        do_div(rout, ack_us);
    }

    mmt->bytes_acked = tp->bytes_acked - ca->last_bytes_acked;
    ca->last_bytes_acked = tp->bytes_acked;

    mmt->packets_misordered = tp->sacked_out - ca->last_sacked_out;
    if (tp->sacked_out < ca->last_sacked_out) {
        mmt->packets_misordered = 0;
    } else {
        mmt->packets_misordered = tp->sacked_out - ca->last_sacked_out;
    }

    ca->last_sacked_out = tp->sacked_out;

    mmt->packets_acked = rs->acked_sacked - mmt->packets_misordered;
    mmt->bytes_misordered = mmt->packets_misordered * tp->mss_cache;
    mmt->lost_pkts_sample = rs->losses;
    mmt->rtt_sample_us = rs->rtt_us;
    if ( rin != 0 ) {
        mmt->rate_outgoing = rin;
    }

    if ( rout != 0 ) {
        mmt->rate_incoming = rout;
    }

    mmt->bytes_in_flight = tcp_packets_in_flight(tp) * tp->mss_cache;
    mmt->packets_in_flight = tcp_packets_in_flight(tp);
    if (tp->snd_cwnd <= 0) {
        return -1;
    }

    mmt->snd_cwnd = tp->snd_cwnd * tp->mss_cache;

    if (unlikely(tp->snd_una > tp->write_seq)) {
        mmt->bytes_pending = ((u32) ~0U) - (tp->snd_una - tp->write_seq);
    } else {
        mmt->bytes_pending = (tp->write_seq - tp->snd_una);
    }

    return 0;
}

void tcp_ccp_cong_control(struct sock *sk, const struct rate_sample *rs) {
    // aggregate measurement
    // state = fold(state, rs)
    int ok;
    struct ccp *ca = inet_csk_ca(sk);
    struct ccp_connection *conn = ca->conn;

#if __IPC__ == IPC_CHARDEV
        ccpkp_try_read();
#endif

    if (conn != NULL) {
        // load primitive registers
        ok = load_primitives(sk, rs);
        if (ok < 0) {
            return;
        }

        ok = ccp_invoke(conn);
        if (ok == LIBCCP_FALLBACK_TIMED_OUT) {
          pr_info("[ccp] libccp fallback timed out");
          // TODO default to cubic?
        }

        ca->conn->prims.was_timeout = false;
    } else {
        pr_info("[ccp] ccp_connection not initialized");
    }
}
EXPORT_SYMBOL_GPL(tcp_ccp_cong_control);

/* Slow start threshold is half the congestion window (min 2) */
u32 tcp_ccp_ssthresh(struct sock *sk) {
    const struct tcp_sock *tp = tcp_sk(sk);

    return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(tcp_ccp_ssthresh);

u32 tcp_ccp_undo_cwnd(struct sock *sk) {
    const struct tcp_sock *tp = tcp_sk(sk);

    return max(tp->snd_cwnd, tp->snd_ssthresh << 1);
}
EXPORT_SYMBOL_GPL(tcp_ccp_undo_cwnd);

void tcp_ccp_pkts_acked(struct sock *sk, const struct ack_sample *sample) {
    struct ccp *cpl;
    s32 sampleRTT;

    cpl = inet_csk_ca(sk);
    sampleRTT = sample->rtt_us;
}
EXPORT_SYMBOL_GPL(tcp_ccp_pkts_acked);

/*
 * Detect drops.
 *
 * TCP_CA_Loss -> a timeout happened
 * TCP_CA_Recovery -> an isolated loss (3x dupack) happened.
 * TCP_CA_CWR -> got an ECN
 */
void tcp_ccp_set_state(struct sock *sk, u8 new_state) {
    struct ccp *cpl = inet_csk_ca(sk);
    switch (new_state) {
        case TCP_CA_Loss:
            if (cpl->conn != NULL) {
                cpl->conn->prims.was_timeout = true;
            }
            ccp_invoke(cpl->conn);
            return;
        case TCP_CA_Recovery:
        case TCP_CA_CWR:
        default:
            break;
    }
            
    if (cpl->conn != NULL) {
        cpl->conn->prims.was_timeout = false;
    }
}
EXPORT_SYMBOL_GPL(tcp_ccp_set_state);

void tcp_ccp_init(struct sock *sk) {
    struct ccp *cpl;
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccp_datapath_info dp_info = {
        .init_cwnd = tp->snd_cwnd * tp->mss_cache,
        .mss = tp->mss_cache,
        .src_ip = tp->inet_conn.icsk_inet.inet_saddr,
        .src_port = tp->inet_conn.icsk_inet.inet_sport,
        .dst_ip = tp->inet_conn.icsk_inet.inet_daddr,
        .dst_port = tp->inet_conn.icsk_inet.inet_dport,
        .congAlg = "reno",
    };

    pr_info("[ccp] new flow\n");
    
    cpl = inet_csk_ca(sk);
    cpl->last_snd_una = tp->snd_una;
    cpl->last_bytes_acked = tp->bytes_acked;
    cpl->last_sacked_out = tp->sacked_out;

    cpl->skb_array = (struct skb_info*)kmalloc(MAX_SKB_STORED * sizeof(struct skb_info), GFP_KERNEL);
    if (!(cpl->skb_array)) {
        pr_info("[ccp] could not allocate skb array\n");
    }
    memset(cpl->skb_array, 0, MAX_SKB_STORED * sizeof(struct skb_info));

    cpl->conn = ccp_connection_start(kernel_datapath, (void *) sk, &dp_info);
    if (cpl->conn == NULL) {
        pr_info("[ccp] start connection failed\n");
    } else {
        pr_info("[ccp] starting connection %d", cpl->conn->index);
    }

    // if no ecn support
    if (!(tp->ecn_flags & TCP_ECN_OK)) {
        INET_ECN_dontxmit(sk);
    }
    
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}
EXPORT_SYMBOL_GPL(tcp_ccp_init);

void tcp_ccp_release(struct sock *sk) {
    struct ccp *cpl = inet_csk_ca(sk);
    if (cpl->conn != NULL) {
        pr_info("[ccp] freeing connection %d", cpl->conn->index);
        ccp_connection_free(kernel_datapath, cpl->conn->index);
    } else {
        pr_info("[ccp] already freed");
    }
    if (cpl->skb_array != NULL) {
        kfree(cpl->skb_array);
        cpl->skb_array = NULL;
    }
}
EXPORT_SYMBOL_GPL(tcp_ccp_release);

struct tcp_congestion_ops tcp_ccp_congestion_ops = {
    .flags = TCP_CONG_NEEDS_ECN,
    .in_ack_event = tcp_ccp_in_ack_event,
    .name = "ccp",
    .owner = THIS_MODULE,
    .init = tcp_ccp_init,
    .release = tcp_ccp_release,
    .ssthresh = tcp_ccp_ssthresh,
    //.cong_avoid = tcp_ccp_cong_avoid,
    .cong_control = tcp_ccp_cong_control,
    .undo_cwnd = tcp_ccp_undo_cwnd,
    .set_state = tcp_ccp_set_state,
    .pkts_acked = tcp_ccp_pkts_acked
};

void ccp_log(struct ccp_datapath *dp, enum ccp_log_level level, const char* msg, int msg_size) {
    switch(level) {
    case ERROR:
    case WARN:
    case INFO:
    case DEBUG:
    case TRACE:
        pr_info("%s\n", msg);
        break;
    default:
        break;
    }
}

static int __init tcp_ccp_register(void) {
    int ok;

    ktime_get_real_ts64(&tzero);

#ifdef COMPAT_MODE
    pr_info("[ccp] Compatibility mode: 4.13 <= kernel version <= 4.16\n");
#endif
#ifdef RATESAMPLE_MODE
    pr_info("[ccp] Rate-sample mode: 4.19 <= kernel version\n");
#endif

    kernel_datapath = kmalloc(sizeof(struct ccp_datapath), GFP_KERNEL);
    if(!kernel_datapath) {
        pr_info("[ccp] could not allocate ccp_datapath\n");
        return -4;
    }

    kernel_datapath->max_connections = MAX_ACTIVE_FLOWS;
    // initializes ccp_active_connections to zeros to support the availability check using index == 0 in ccp_connection_start()
    kernel_datapath->ccp_active_connections =
        (struct ccp_connection *) kzalloc(sizeof(struct ccp_connection) * MAX_ACTIVE_FLOWS, GFP_KERNEL);
    if(!kernel_datapath->ccp_active_connections) {
        pr_info("[ccp] could not allocate ccp_active_connections\n");
        return -5;
    }

    kernel_datapath->max_programs = MAX_DATAPATH_PROGRAMS;
    kernel_datapath->set_cwnd = &do_set_cwnd;
    kernel_datapath->set_rate_abs = &do_set_rate_abs;
    kernel_datapath->now = &ccp_now;
    kernel_datapath->since_usecs = &ccp_since;
    kernel_datapath->after_usecs = &ccp_after;
    kernel_datapath->log = &ccp_log;
    kernel_datapath->fto_us = 1000;
#if __IPC__ == IPC_NETLINK
    ok = ccp_nl_sk(&ccp_read_msg);
    if (ok < 0) {
        return -1;
    }

    kernel_datapath->send_msg = &nl_sendmsg;
    pr_info("[ccp] ipc = netlink\n");
#elif __IPC__ == IPC_CHARDEV
    ok = ccpkp_init(&ccp_read_msg);
    if (ok < 0) {
        return -2;
    }

    kernel_datapath->send_msg = &ccpkp_sendmsg;
    pr_info("[ccp] ipc = chardev\n");
#else
    pr_info("[ccp] ipc =  %s unknown\n", __IPC__);
    return -3;
#endif
	
    ok = ccp_init(kernel_datapath, 0);
    if (ok < 0) {
        pr_info("[ccp] ccp_init failed: %d\n", ok);
#if __IPC__ == IPC_NETLINK
        free_ccp_nl_sk();
#elif __IPC__ == IPC_CHARDEV
        ccpkp_cleanup();
#endif
        return -6;
    }

    pr_info("[ccp] init\n");
    return tcp_register_congestion_control(&tcp_ccp_congestion_ops);
}

static void __exit tcp_ccp_unregister(void) {
    tcp_unregister_congestion_control(&tcp_ccp_congestion_ops);
#if __IPC__ == IPC_NETLINK
    free_ccp_nl_sk();
#elif __IPC__ == IPC_CHARDEV
    ccpkp_cleanup();
#endif
    kfree(kernel_datapath->ccp_active_connections);
    kfree(kernel_datapath);
    pr_info("[ccp] exit\n");
}

module_init(tcp_ccp_register);
module_exit(tcp_ccp_unregister);

MODULE_AUTHOR("Akshay Narayan <akshayn@mit.edu>");
MODULE_DESCRIPTION("Kernel datapath for a congestion control plane");
MODULE_LICENSE("GPL");
