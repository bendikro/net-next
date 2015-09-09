#include <linux/skbuff.h>
#include <net/tcp.h>

int sysctl_tcp_rdb_max_bytes __read_mostly;
int sysctl_tcp_rdb_max_packets __read_mostly = 1;

/**
 * rdb_check_rtx_queue_loss() - perform loss detection by analysing ACKs
 * @sk: socket
 *
 * Return: The number of packets that are presumed to be lost
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
 * rdb_ack_event() - initiate loss detection
 * @sk: socket
 * @flags: flags
 */
void rdb_ack_event(struct sock *sk, u32 flags)
{
	if (rdb_check_rtx_queue_loss(sk))
		tcp_enter_cwr(sk);
}

/**
 * rdb_build_skb() - build the new RDB SKB and copy all the data into the
 *                   linear page buffer
 * @sk: socket
 * @xmit_skb: the SKB processed for transmission in the output engine
 * @first_skb: the first SKB in the output queue to be bundled
 * @bytes_in_rdb_skb: the total number of data bytes for the new rdb_skb
 *                    (NEW + Redundant)
 * @gfp_mask: gfp_t allocation
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
	struct sk_buff *rdb_skb, *tmp_skb = first_skb;

	rdb_skb = sk_stream_alloc_skb((struct sock *)sk,
				      (int)bytes_in_rdb_skb,
				      gfp_mask, true);
	if (!rdb_skb)
		return NULL;
	copy_skb_header(rdb_skb, xmit_skb);
	rdb_skb->ip_summed = xmit_skb->ip_summed;
	TCP_SKB_CB(rdb_skb)->seq = TCP_SKB_CB(first_skb)->seq;
	TCP_SKB_CB(xmit_skb)->tx.rdb_start_seq = TCP_SKB_CB(rdb_skb)->seq;

	tcp_for_write_queue_from(tmp_skb, sk) {
		/* Copy data from tmp_skb to rdb_skb */
		tcp_skb_append_data(tmp_skb, rdb_skb);

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
 * @sk: socket
 * @xmit_skb: the SKB processed for transmission by the output engine
 * @max_payload: the maximum allowed payload bytes for the RDB SKB
 * @bytes_in_rdb_skb: store the total number of payload bytes in the
 *                    RDB SKB if bundling can be performed
 *
 * Traverse the output queue and check if any un-acked data may be
 * bundled.
 *
 * Return: The first SKB to be in the bundle, or NULL if no bundling
 */
static struct sk_buff *rdb_can_bundle_test(const struct sock *sk,
					   struct sk_buff *xmit_skb,
					   unsigned int max_payload,
					   u32 *bytes_in_rdb_skb)
{
	struct sk_buff *first_to_bundle = NULL;
	struct sk_buff *tmp, *skb = xmit_skb->prev;
	u32 skbs_in_bundle_count = 1; /* Start on 1 to account for xmit_skb */
	u32 total_payload = xmit_skb->len;

	if (sysctl_tcp_rdb_max_bytes)
		max_payload = min(max_payload, (unsigned int) sysctl_tcp_rdb_max_bytes);

	/* We start at xmit_skb->prev, and go backwards. */
	tcp_for_write_queue_reverse_from_safe(skb, tmp, sk) {
		if ((total_payload + skb->len) > max_payload)
			break;

		if (sysctl_tcp_rdb_max_packets &&
		    (skbs_in_bundle_count > sysctl_tcp_rdb_max_packets))
			break;

		total_payload += skb->len;
		skbs_in_bundle_count++;
		first_to_bundle = skb;
	}
	*bytes_in_rdb_skb = total_payload;
	return first_to_bundle;
}

/**
 * tcp_transmit_rdb_skb() - try to create and send an RDB packet
 * @sk: socket
 * @xmit_skb: the SKB processed for transmission by the output engine
 * @mss_now: current mss value
 * @gfp_mask: gfp_t allocation
 *
 * If an RDB packet could not be created and sent, transmit the
 * original unmodified SKB (xmit_skb).
 *
 * Return: 0 if successfully sent packet, else error
 */
int tcp_transmit_rdb_skb(struct sock *sk, struct sk_buff *xmit_skb,
			 unsigned int mss_now, gfp_t gfp_mask)
{
	struct sk_buff *rdb_skb = NULL;
	struct sk_buff *first_to_bundle;
	u32 bytes_in_rdb_skb = 0;

	/* How we detect that RDB was used. When equal, no RDB data was sent */
	TCP_SKB_CB(xmit_skb)->tx.rdb_start_seq = TCP_SKB_CB(xmit_skb)->seq;

	if (!tcp_stream_is_thin_dpifl(tcp_sk(sk)))
		goto xmit_default;

	/* No bundling if first in queue, or on FIN packet */
	if (skb_queue_is_first(&sk->sk_write_queue, xmit_skb) ||
		(TCP_SKB_CB(xmit_skb)->tcp_flags & TCPHDR_FIN))
		goto xmit_default;

	/* Find number of (previous) SKBs to get data from */
	first_to_bundle = rdb_can_bundle_test(sk, xmit_skb, mss_now,
					      &bytes_in_rdb_skb);
	if (!first_to_bundle)
		goto xmit_default;

	/* Create an SKB that contains redundant data starting from
	 * first_to_bundle.
	 */
	rdb_skb = rdb_build_skb(sk, xmit_skb, first_to_bundle,
				bytes_in_rdb_skb, gfp_mask);
	if (!rdb_skb)
		goto xmit_default;

	/* Set tstamp for SKB in output queue, because tcp_transmit_skb
	 * will do this for the rdb_skb and not the SKB in the output
	 * queue (xmit_skb).
	 */
	skb_mstamp_get(&xmit_skb->skb_mstamp);
	rdb_skb->skb_mstamp = xmit_skb->skb_mstamp;
	return tcp_transmit_skb(sk, rdb_skb, 0, gfp_mask);

xmit_default:
	/* Transmit the unmodified SKB from output queue */
	return tcp_transmit_skb(sk, xmit_skb, 1, gfp_mask);
}
