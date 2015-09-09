#include <linux/skbuff.h>
#include <net/tcp.h>

int sysctl_tcp_rdb_max_bytes __read_mostly;
int sysctl_tcp_rdb_max_skbs __read_mostly = 1;

/**
 * rdb_check_rtx_queue_loss() - Perform loss detection by analysing acks.
 * @sk: the socket.
 *
 * Return: The number of packets that are presumed to be lost.
 */
static unsigned int rdb_check_rtx_queue_loss(struct sock *sk)
{
	struct sk_buff *skb, *tmp;
	struct tcp_skb_cb *scb;
	u32 seq_acked = tcp_sk(sk)->snd_una;
	unsigned int packets_lost = 0;

	tcp_for_write_queue(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;

		scb = TCP_SKB_CB(skb);
		/* The ACK acknowledges parts of the data in this SKB.
		 * Can be caused by:
		 * - TSO: We abort as RDB is not used on SKBs split across
		 *        multiple packets on lower layers as these are greater
		 *        than one MSS.
		 * - Retrans collapse: We've had a retrans, so loss has already
		 *                     been detected.
		 */
		if (after(scb->end_seq, seq_acked)) {
			break;
		/* The ACKed packet */
		} else if (scb->end_seq == seq_acked) {
			/* This SKB was sent with no RDB data, or no prior
			 * unacked SKBs in output queue, so break here.
			 */
			if (scb->tx.rdb_start_seq == scb->seq ||
			    skb_queue_is_first(&sk->sk_write_queue, skb))
				break;
			/* Find number of prior SKBs who's data was bundled in
			 * this (ACKed) SKB. We presume any redundant data
			 * covering previous SKB's are due to loss. (An
			 * exception would be reordering).
			 */
			skb = skb->prev;
			tcp_for_write_queue_reverse_from_safe(skb, tmp, sk) {
				if (!before(TCP_SKB_CB(skb)->seq, scb->tx.rdb_start_seq))
					packets_lost++;
				else
					break;
			}
			break;
		}
	}
	return packets_lost;
}

/**
 * rdb_ack_event() - Initiate loss detection
 * @sk: the socket
 * @flags: The flags
 */
void rdb_ack_event(struct sock *sk, u32 flags)
{
	if (rdb_check_rtx_queue_loss(sk))
		tcp_enter_cwr(sk);
}

/**
 * skb_append_data() - Copy data from an SKB to the end of another
 * @from_skb: The SKB to copy data from
 * @to_skb: The SKB to copy data to
 *
 * Return: 0 on success, else error
 */
static int skb_append_data(struct sk_buff *from_skb, struct sk_buff *to_skb)
{
	/* Copy the linear data and the data from the frags into the linear page
	 * buffer of to_skb.
	 */
	if (WARN_ON(skb_copy_bits(from_skb, 0,
				  skb_put(to_skb, from_skb->len),
				  from_skb->len))) {
		goto fault;
	}

	TCP_SKB_CB(to_skb)->end_seq = TCP_SKB_CB(from_skb)->end_seq;

	if (from_skb->ip_summed == CHECKSUM_PARTIAL)
		to_skb->ip_summed = CHECKSUM_PARTIAL;

	if (to_skb->ip_summed != CHECKSUM_PARTIAL)
		to_skb->csum = csum_block_add(to_skb->csum, from_skb->csum,
					      to_skb->len);
	return 0;
fault:
	return -EFAULT;
}

/**
 * rdb_build_skb() - Builds the new RDB SKB and copies all the data into the
 *                   linear page buffer.
 * @sk: the socket
 * @xmit_skb: This is the SKB that tcp_write_xmit wants to send
 * @first_skb: The first SKB in the output queue we will bundle
 * @gfp_mask: The gfp_t allocation
 * @bytes_in_rdb_skb: The total number of data bytes for the new rdb_skb
 *                         (NEW + Redundant)
 *
 * Return: A new SKB containing redundant data, or NULL if memory allocation
 *         failed
 */
static struct sk_buff *rdb_build_skb(const struct sock *sk,
				     struct sk_buff *xmit_skb,
				     struct sk_buff *first_skb,
				     u32 bytes_in_rdb_skb,
				     gfp_t gfp_mask)
{
	struct sk_buff *rdb_skb, *tmp_skb;

	rdb_skb = sk_stream_alloc_skb((struct sock *)sk,
				      (int)bytes_in_rdb_skb,
				      gfp_mask, true);
	if (!rdb_skb)
		return NULL;
	copy_skb_header(rdb_skb, xmit_skb);
	rdb_skb->ip_summed = xmit_skb->ip_summed;

	TCP_SKB_CB(rdb_skb)->seq = TCP_SKB_CB(first_skb)->seq;
	TCP_SKB_CB(xmit_skb)->tx.rdb_start_seq = TCP_SKB_CB(rdb_skb)->seq;

	tmp_skb = first_skb;

	tcp_for_write_queue_from(tmp_skb, sk) {
		/* Copy data from tmp_skb to rdb_skb */
		if (skb_append_data(tmp_skb, rdb_skb))
			return NULL;
		/* We are at the last skb that should be included (The unsent
		 * one)
		 */
		if (tmp_skb == xmit_skb)
			break;
	}
	return rdb_skb;
}

/**
 * rdb_can_bundle_test() - test if redundant data can be bundled
 * @sk: the socket
 * @xmit_skb: The SKB processed for transmission by the output engine
 * @mss_now: The current mss value
 * @bytes_in_rdb_skb: Will contain the resulting number of bytes to bundle
 *                         at exit.
 * @skbs_to_bundle_count: The total number of SKBs to be in the bundle
 *
 * Traverses the entire write queue and checks if any un-acked data
 * may be bundled.
 *
 * Return: The first SKB to be in the bundle, or NULL if no bundling
 */
static struct sk_buff *rdb_can_bundle_test(const struct sock *sk,
					    struct sk_buff *xmit_skb,
					    unsigned int mss_now,
					    u32 *bytes_in_rdb_skb,
					    u32 *skbs_to_bundle_count)
{
	struct sk_buff *first_to_bundle = NULL;
	struct sk_buff *tmp, *skb = xmit_skb->prev;
	u32 skbs_in_bundle_count = 1; /* 1 to account for current skb */
	u32 byte_count = xmit_skb->len;

	/* We start at the skb before xmit_skb, and go backwards in the list.*/
	tcp_for_write_queue_reverse_from_safe(skb, tmp, sk) {
		/* Not enough room to bundle data from this SKB */
		if ((byte_count + skb->len) > mss_now)
			break;

		if (sysctl_tcp_rdb_max_bytes &&
		    ((byte_count + skb->len) > sysctl_tcp_rdb_max_bytes))
			break;

		if (sysctl_tcp_rdb_max_skbs &&
		    (skbs_in_bundle_count > sysctl_tcp_rdb_max_skbs))
			break;

		byte_count += skb->len;
		skbs_in_bundle_count++;
		first_to_bundle = skb;
	}
	*bytes_in_rdb_skb = byte_count;
	*skbs_to_bundle_count = skbs_in_bundle_count;
	return first_to_bundle;
}

/**
 * create_rdb_skb() - Try to create an RDB SKB
 * @sk: the socket
 * @xmit_skb: The SKB from the output queue to be sent
 * @mss_now: Current MSS
 * @gfp_mask: The gfp_t allocation
 *
 * Return: A new SKB containing redundant data, or NULL if no bundling could be
 *         performed
 */
struct sk_buff *create_rdb_skb(const struct sock *sk, struct sk_buff *xmit_skb,
			       unsigned int mss_now, u32 *bytes_in_rdb_skb,
			       gfp_t gfp_mask)
{
	u32 skb_in_bundle_count;
	struct sk_buff *first_to_bundle;

	if (skb_queue_is_first(&sk->sk_write_queue, xmit_skb))
		return NULL;

	/* No bundling on FIN packet */
	if (TCP_SKB_CB(xmit_skb)->tcp_flags & TCPHDR_FIN)
		return NULL;

	/* Find number of (previous) SKBs to get data from */
	first_to_bundle = rdb_can_bundle_test(sk, xmit_skb, mss_now,
					       bytes_in_rdb_skb,
					       &skb_in_bundle_count);
	if (!first_to_bundle)
		return NULL;

	/* Create an SKB that contains the data from 'skb_in_bundle_count'
	 * SKBs.
	 */
	return rdb_build_skb(sk, xmit_skb, first_to_bundle,
			     *bytes_in_rdb_skb, gfp_mask);
}

/**
 * tcp_transmit_rdb_skb() - Try to create and send an RDB packet
 * @sk: the socket
 * @xmit_skb: The SKB processed for transmission by the output engine
 * @mss_now: Current MSS
 * @gfp_mask: The gfp_t allocation
 *
 * Return: 0 if successfully sent packet, else error
 */
int tcp_transmit_rdb_skb(struct sock *sk, struct sk_buff *xmit_skb,
			 unsigned int mss_now, gfp_t gfp_mask)
{
	struct sk_buff *rdb_skb = NULL;
	u32 bytes_in_rdb_skb = 0; /* May be used for statistical purposes */

	/* How we detect that RDB was used. When equal, no RDB data was sent */
	TCP_SKB_CB(xmit_skb)->tx.rdb_start_seq = TCP_SKB_CB(xmit_skb)->seq;

	if (tcp_stream_is_thin_dpifl(tcp_sk(sk))) {
		rdb_skb = create_rdb_skb(sk, xmit_skb, mss_now,
					 &bytes_in_rdb_skb, gfp_mask);
		if (!rdb_skb)
			goto xmit_default;

		/* Set tstamp for SKB in output queue, because tcp_transmit_skb
		 * will do this for the rdb_skb and not the SKB in the output
		 * queue (xmit_skb).
		 */
		skb_mstamp_get(&xmit_skb->skb_mstamp);
		rdb_skb->skb_mstamp = xmit_skb->skb_mstamp;
		return tcp_transmit_skb(sk, rdb_skb, 0, gfp_mask);
	}
xmit_default:
	/* Transmit the unmodified SKB from output queue */
	return tcp_transmit_skb(sk, xmit_skb, 1, gfp_mask);
}
