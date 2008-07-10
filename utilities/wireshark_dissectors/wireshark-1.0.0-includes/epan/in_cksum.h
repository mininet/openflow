/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id: in_cksum.h 3992 2008-06-10 03:13:11Z dgu $
 */

typedef struct {
	const guint8 *ptr;
	int	len;
} vec_t;

extern int in_cksum(const vec_t *vec, int veclen);

extern guint16 in_cksum_shouldbe(guint16 sum, guint16 computed_sum);
