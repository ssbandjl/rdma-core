/******************************************************************************
*
* RDMA Aware Networks Programming Example
*
* This code demonstrates how to perform the following operations using the * VPI Verbs API:
*
* Send
* Receive
* RDMA Read
* RDMA Write
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>

#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define ROCEV2_PORT_NUM 1
#define ROCEV2_PORT_NUM_IDX 3 /* show_gids |grep v2 */

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 20000
#define MSG "SEND operation "
#define MSG_SIZE 1048576 //1MB
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

#define FFL_FMT              "%s() %s:%d"
#define FFL                  __FUNCTION__,__FILE__,__LINE__

#define DEBUG(fmt, ...) \
do { \
  fprintf(stdout, ""FFL_FMT", ", FFL); \
  fprintf(stdout, fmt, ##__VA_ARGS__); \
} while (0)

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t
{
	uint64_t addr;		/* Buffer address */
	uint32_t rkey;		/* Remote key */
	uint32_t qp_num;	/* QP number */
	uint16_t lid;		/* LID of the IB port */
	char gid[33];
} __attribute__((packed));

/* structure of system resources */
struct resources
{
	struct ibv_device_attr device_attr; /* Device attributes */
	struct ibv_port_attr port_attr;		/* IB port attributes */
	struct cm_con_data_t remote_props;  /* values to connect to remote side */
	struct ibv_context *ib_ctx;			/* device handle */
	struct ibv_pd *pd;					/* PD handle */
	struct ibv_cq *cq;					/* CQ handle */
	struct ibv_qp *qp;					/* QP handle */
	struct ibv_mr *mr;					/* MR handle for buf */
	char *buf;							/* memory buffer pointer */
};

/******************************************************************************
* Function: sock_connect
*
* Input
* servername URL of server to connect to (NULL for server mode)
* port port of service
*
* Output
* none
*
* Returns
* socket (fd) on success, negative error code on failure
*
* Description
* Connect a socket. If servername is specified a client connection will be
* initiated to the indicated server and port. Otherwise listen on the
* indicated port for an incoming connection.
*
******************************************************************************/
static int sock_connect(const char *servername, int port)
{
	struct addrinfo *resolved_addr = NULL;
	struct addrinfo *iterator;
	char service[6];
	int sockfd = -1;
	int listenfd = 0;
	int tmp;
	struct addrinfo hints =
		{
			.ai_flags = AI_PASSIVE,
			.ai_family = AF_INET,
			.ai_socktype = SOCK_STREAM};

	if (sprintf(service, "%d", port) < 0)
		goto sock_connect_exit;
	/* Resolve DNS address, use sockfd as temp storage */
	sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
	if (sockfd < 0)
	{
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), servername, port);
		goto sock_connect_exit;
	}
	/* Search through results and find the one we want */
	for (iterator = resolved_addr; iterator; iterator = iterator->ai_next)
	{
		sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
		if (sockfd >= 0)
		{
			if (servername)
			{
				/* Client mode. Initiate connection to remote */
				if ((tmp = connect(sockfd, iterator->ai_addr, iterator->ai_addrlen)))
				{
					DEBUG("failed connect \n");
					close(sockfd);
					sockfd = -1;
				}
			}
			else
			{
				/* Server mode. Set up listening socket an accept a connection */
				listenfd = sockfd;
				sockfd = -1;
				if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
					goto sock_connect_exit;
				listen(listenfd, 1);
				sockfd = accept(listenfd, NULL, 0);
			}
		}
	}
sock_connect_exit:
	if (listenfd)
		close(listenfd);
	if (resolved_addr)
		freeaddrinfo(resolved_addr);
	if (sockfd < 0)
	{
		if (servername)
			fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
		else
		{
			perror("server accept");
			fprintf(stderr, "accept() failed\n");
		}
	}
	return sockfd;
}

/******************************************************************************
* Function: sock_sync_data
*
* Input
Table 5 -
* sock socket to transfer data on
* xfer_size size of data to transfer
* local_data pointer to data to be sent to remote (local_data是一个指向要发送到远程的数据的指针)
*
* Output
* remote_data pointer to buffer to receive remote data
*
* Returns
* 0 on success, negative error code on failure
*
* Description
* Sync data across a socket. The indicated local data will be sent to the
* remote. It will then wait for the remote to send its data back. It is
* assumed that the two sides are in sync and call this function in the proper
* order. Chaos will ensue if they are not. :)
*
* Also note this is a blocking function and will wait for the full data to be
* received from the remote.
*
******************************************************************************/
int sock_sync_data(char *server_ip, int xfer_size, char *local_data, char *remote_data)
{
	int sock = -1;
	int port = 10002;
	int rc;
	if (server_ip)
	{
		sock = sock_connect(server_ip, port);
		if (sock < 0)
		{
			fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n",
					server_ip, port);
			rc = -1;
		}
	}
	else
	{
		DEBUG("waiting on port %d for TCP connection\n", port);
		sock = sock_connect(NULL, port);
		if (sock < 0)
		{
			fprintf(stderr, "failed to establish TCP connection with client\n");
			rc = -1;
		}
	}
	DEBUG("TCP connection was established\n");
	int read_bytes = 0;
	int total_read_bytes = 0;
	rc = write(sock, local_data, xfer_size);
	if (rc < xfer_size)
		fprintf(stderr, "Failed writing data during sock_sync_data\n");
	else
		rc = 0;
	while (!rc && total_read_bytes < xfer_size)
	{
		read_bytes = read(sock, remote_data, xfer_size);
		if (read_bytes > 0)
			total_read_bytes += read_bytes;
		else
			rc = read_bytes;
	}

	sleep(2); //sleep 2s
	if (sock > 0)
		close(sock);
	return rc;
}
/******************************************************************************
End of socket operations
******************************************************************************/

/* poll_completion */
/******************************************************************************
* Function: poll_completion
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Poll the completion queue for a single event. This function will continue to
* poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed. (轮询获得一个CQ事件)
*
******************************************************************************/
static int poll_completion(struct resources *res)
{
	/* 13 轮询任务结果 */
	struct ibv_wc wc;
	int poll_result;
	int rc = 0;
	do
	{
		poll_result = ibv_poll_cq(res->cq, 1, &wc);
	} while (poll_result == 0);

	if (poll_result < 0)
	{
		/* poll CQ failed */
		fprintf(stderr, "poll CQ failed\n");
		rc = 1;
	}
	else
	{
		if (wc.status != IBV_WC_SUCCESS)
		{
			fprintf(stderr, "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n", wc.status,
					wc.vendor_err);
			rc = 1;
		}
	}
	return rc;
}

/******************************************************************************
* Function: post_send
*
* Input
* res pointer to resources structure
* opcode IBV_WR_SEND, IBV_WR_RDMA_READ or IBV_WR_RDMA_WRITE
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
* This function will create and post a send work request
******************************************************************************/
static int post_send(struct resources *res, int opcode)
{
	/* 11 创建发送任务ibv_send_wr */
	struct ibv_send_wr sr;
	struct ibv_sge sge;
	struct ibv_send_wr *bad_wr = NULL;
	int rc;
	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->buf;
	sge.length = MSG_SIZE;
	sge.lkey = res->mr->lkey;
	/* prepare the send work request */
	memset(&sr, 0, sizeof(sr));
	sr.next = NULL;
	sr.wr_id = 0;
	sr.sg_list = &sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
	sr.send_flags = IBV_SEND_SIGNALED;
	if (opcode != IBV_WR_SEND)
	{
		sr.wr.rdma.remote_addr = res->remote_props.addr;
		sr.wr.rdma.rkey = res->remote_props.rkey;
	}
	/* 12 提交发送任务 */
	rc = ibv_post_send(res->qp, &sr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post SR\n");
	return rc;
}

/******************************************************************************
* Function: post_receive
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
*
******************************************************************************/
static int post_receive(struct resources *res)
{
	/* 11 创建接收任务ibv_resv_wr */
	struct ibv_recv_wr rr;
	struct ibv_sge sge;
	struct ibv_recv_wr *bad_wr;
	int rc;
	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->buf;
	sge.length = MSG_SIZE;
	sge.lkey = res->mr->lkey;
	/* prepare the receive work request */
	memset(&rr, 0, sizeof(rr));
	rr.next = NULL;
	rr.wr_id = 0;
	rr.sg_list = &sge;
	rr.num_sge = 1;
	/* 12 提交接收任务 */
	rc = ibv_post_recv(res->qp, &rr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post RR\n");
	return rc;
}

/******************************************************************************
* Function: resources_destroy
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Cleanup and deallocate all resources used
******************************************************************************/
static int resources_destroy(struct resources *res)
{
	int rc = 0;
	if (res->qp)
		if (ibv_destroy_qp(res->qp))
		{
			fprintf(stderr, "failed to destroy QP\n");
			rc = 1;
		}
	if (res->mr)
		if (ibv_dereg_mr(res->mr))
		{
			fprintf(stderr, "failed to deregister MR\n");
			rc = 1;
		}
	if (res->buf)
		free(res->buf);
	if (res->cq)
		if (ibv_destroy_cq(res->cq))
		{
			fprintf(stderr, "failed to destroy CQ\n");
			rc = 1;
		}
	if (res->pd)
		if (ibv_dealloc_pd(res->pd))
		{
			fprintf(stderr, "failed to deallocate PD\n");
			rc = 1;
		}
	if (res->ib_ctx)
		if (ibv_close_device(res->ib_ctx))
		{
			fprintf(stderr, "failed to close device context\n");
			rc = 1;
		}
	return rc;
}

void gid_to_wire_gid(const union ibv_gid *gid, char wgid[])
{
	uint32_t tmp_gid[4];
	int i;

	memcpy(tmp_gid, gid, sizeof(tmp_gid));
	for (i = 0; i < 4; ++i)
		sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
}


void wire_gid_to_gid(const char *wgid, union ibv_gid *gid)
{
	char tmp[9];
	__be32 v32;
	int i;
	uint32_t tmp_gid[4];

	for (tmp[8] = 0, i = 0; i < 4; ++i) {
		memcpy(tmp, wgid + i * 8, 8);
		sscanf(tmp, "%x", &v32);
		tmp_gid[i] = be32toh(v32);
	}
	memcpy(gid, tmp_gid, sizeof(*gid));
}

/******************************************************************************
* Function: main
*
* Input
* argc number of items in argv
* argv command line parameters
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Main program code
******************************************************************************/
int main(int argc, char *argv[])
{
	struct resources res;
	int rc = 1;
	int ib_port = 1;
	int gidx = 3;
	union ibv_gid gid;


	char *server_ip = NULL;
	if (optind == argc - 1)
		server_ip = argv[optind]; //获取客户端连接服务器的IP

	/* init all of the resources, so cleanup will be easy */
	memset(&res, 0, sizeof res);

	/* 1 获取设备列表 */
	int num_devices;
	struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
	if (!dev_list || !num_devices)
	{
		fprintf(stderr, "failed to get IB devices\n");
		rc = 1;
		goto main_exit;
	}

	/* 2 打开设备，获取设备上下文 */
	struct ibv_device *ib_dev = dev_list[0];
	DEBUG("Open dev_name:%s\n", ib_dev->name);
	res.ib_ctx = ibv_open_device(ib_dev);
	if (!res.ib_ctx)
	{
		fprintf(stderr, "failed to open device \n");
		rc = 1;
		goto main_exit;
	}

	/* 3 释放设备列表占用的资源 */
	ibv_free_device_list(dev_list);
	dev_list = NULL;
	ib_dev = NULL;

	/* 4 查询设备端口状态 */
	if (ibv_query_port(res.ib_ctx, ib_port, &res.port_attr))
	{
		fprintf(stderr, "ibv_query_port on port failed\n");
		rc = 1;
		goto main_exit;
	}

	/* 5 创建PD（Protection Domain） */
	res.pd = ibv_alloc_pd(res.ib_ctx);
	if (!res.pd)
	{
		fprintf(stderr, "ibv_alloc_pd failed\n");
		rc = 1;
		goto main_exit;
	}

	/* 6 创建CQ（Complete Queue） */
	int cq_size = 10;
	res.cq = ibv_create_cq(res.ib_ctx, cq_size, NULL, NULL, 0);
	if (!res.cq)
	{
		fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
		rc = 1;
		goto main_exit;
	}

	/* 7 注册MR（Memory Region） */
	int size = MSG_SIZE;
	res.buf = (char *)malloc(size);
	if (!res.buf)
	{
		fprintf(stderr, "failed to malloc %u bytes to memory buffer\n", size);
		rc = 1;
		goto main_exit;
	}
	memset(res.buf, 0, size);

	int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	res.mr = ibv_reg_mr(res.pd, res.buf, size, mr_flags);
	if (!res.mr)
	{
		fprintf(stderr, "ibv_reg_mr failed with mr_flags=0x%x\n", mr_flags);
		rc = 1;
		goto main_exit;
	}
	DEBUG("MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
			res.buf, res.mr->lkey, res.mr->rkey, mr_flags);

	/* 8 创建QP（Queue Pair） */
	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 1;
	qp_init_attr.send_cq = res.cq;
	qp_init_attr.recv_cq = res.cq;
	qp_init_attr.cap.max_send_wr = 1;
	qp_init_attr.cap.max_recv_wr = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	res.qp = ibv_create_qp(res.pd, &qp_init_attr);
	if (!res.qp)
	{
		fprintf(stderr, "failed to create QP\n");
		rc = 1;
		goto main_exit;
	}
	DEBUG("QP was created, QP number=0x%x\n", res.qp->qp_num);

	/* 9 交换控制信息 */
	struct cm_con_data_t local_con_data;  // 发送给远程主机的信息
	struct cm_con_data_t remote_con_data; // 接收远程主机发送过来的信息
	struct cm_con_data_t tmp_con_data;

	local_con_data.addr = htonll((uintptr_t)res.buf);
	local_con_data.rkey = htonl(res.mr->rkey);
	local_con_data.qp_num = htonl(res.qp->qp_num);
	local_con_data.lid = htons(res.port_attr.lid);
	DEBUG("Local LID = 0x%x\n", res.port_attr.lid);

	if (ibv_query_gid(res.ib_ctx, ib_port, gidx, &gid)) {
		fprintf(stderr, "can't read sgid of index %d\n", gidx);
		goto main_exit;
	}
	inet_ntop(AF_INET6, &gid, local_con_data.gid, sizeof gid);
	gid_to_wire_gid(&gid, local_con_data.gid);
	DEBUG("local address:  LID 0x%04x, QPN 0x%06x, GID %s\n",
		res.port_attr.lid, local_con_data.qp_num, local_con_data.gid);

	if (sock_sync_data(server_ip, sizeof(struct cm_con_data_t), (char *)&local_con_data, (char *)&tmp_con_data) < 0)
	{
		fprintf(stderr, "failed to exchange connection data between sides\n");
		rc = 1;
		goto main_exit;
	}
	remote_con_data.addr = ntohll(tmp_con_data.addr);
	remote_con_data.rkey = ntohl(tmp_con_data.rkey);
	remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
	remote_con_data.lid = ntohs(tmp_con_data.lid);
	wire_gid_to_gid(tmp_con_data.gid, &gid);
	/* save the remote side attributes, we will need it for the post SR */
	res.remote_props = remote_con_data;
	DEBUG("Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
	DEBUG("Remote rkey = 0x%x\n", remote_con_data.rkey);
	DEBUG("Remote QP number = 0x%x\n", remote_con_data.qp_num);
	DEBUG("Remote LID = 0x%x\n", remote_con_data.lid);
	DEBUG("Remote GID = %s\n", tmp_con_data.gid);

	/* 10 转换QP状态 */
	// RESET -> INIT
	struct ibv_qp_attr attr;
	int flags;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = 1; // IB 端口号
	attr.pkey_index = 0;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
	rc = ibv_modify_qp(res.qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to INIT\n");


	//INIT -> RTR(Ready To Receive)
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_256;
	attr.dest_qp_num = res.remote_props.qp_num;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.is_global = 0;
	attr.ah_attr.dlid = res.remote_props.lid;
	attr.ah_attr.sl = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num = 1;

	if (gid.global.interface_id) {
		DEBUG("Enable gid global interface\n");
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = gid;
		attr.ah_attr.grh.sgid_index = gidx;
	}

	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	rc = ibv_modify_qp(res.qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTR\n");

	//RTR -> RTS(Ready To Send)
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 0;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;
	flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	rc = ibv_modify_qp(res.qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTS\n");

	int choice;
	while (1)
	{
		printf("\n\n\n");
		printf("*********************************************************************************************\n");
		printf("* 1:RDMA_READ 2:RDMA_WRITE 3:SEND 4:RECEIVE 5:Read Local Buffer 6:Write Local Buffer 7:Exit *\n");
		printf("*********************************************************************************************\n");
		printf("please input your choice : ");
		scanf("%d", &choice);
		getchar();
		switch (choice)
		{
		case 1:
			memset(res.buf, 0, MSG_SIZE);
			post_send(&res, IBV_WR_RDMA_READ);
			if (poll_completion(&res))
			{
				fprintf(stderr, "poll completion failed 2\n");
			}
			else
			{
				printf("Reading remote's buffer(addr:0x%lx, rkey:0x%x) : %s\n", res.remote_props.addr, res.remote_props.rkey, res.buf);
			}
			break;

		case 2:
			memset(res.buf, 0, MSG_SIZE);
			printf("Writing remote's buffer(addr:0x%lx, rkey:0x%x) : ", res.remote_props.addr, res.remote_props.rkey);
			fgets(res.buf, MSG_SIZE, stdin);
			post_send(&res, IBV_WR_RDMA_WRITE);
			if (poll_completion(&res))
			{
				fprintf(stderr, "poll completion failed 2\n");
			}
			else
			{
				printf("success\n");
			}
			break;

		case 3:
			memset(res.buf, 0, MSG_SIZE);
			printf("Sending : ");
			fgets(res.buf, MSG_SIZE, stdin);
			post_send(&res, IBV_WR_SEND);
			if (poll_completion(&res))
			{
				fprintf(stderr, "poll completion failed 2\n");
			}
			else
			{
				printf("success\n");
			}
			break;

		case 4:
			printf("receiving: ");
			post_receive(&res);
			if (poll_completion(&res))
			{
				fprintf(stderr, "poll completion failed 2\n");
			}
			else
			{
				printf("%s", res.buf);
			}
			break;

		case 5:
			printf("Reading local buffer(addr:0x%lx): %s\n", (uintptr_t)res.buf, res.buf);
			break;

		case 6:
			memset(res.buf, 0, MSG_SIZE);
			printf("Writing local buffer(addr:0x%lx) : %s", (uintptr_t)res.buf, res.buf);
			fgets(res.buf, MSG_SIZE, stdin);
			break;

		case 7:
			goto main_exit;

		default:
			printf("invalid choice.\n");
			break;
		}
	}

	rc = 0;
main_exit:
	if (resources_destroy(&res))
	{
		fprintf(stderr, "failed to destroy resources\n");
		rc = 1;
	}
	DEBUG("\ntest result is %d\n", rc);
	return rc;
}