/*
 * squashfs with lzma compression
 *
 * Copyright (C) 2010, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: sqlzma.h,v 1.3 2009/03/10 08:42:14 Exp $
 */
#ifndef __sqlzma_h__
#define __sqlzma_h__

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>
#endif

/*
 * detect the compression method automatically by the first byte of compressed
 * data.
 */
#define is_lzma(c)	(c == 0x5d)

int LzmaUncompress(char *dst, unsigned long * dstlen, char *src, int srclen);
int LzmaCompress(char *in_data, int in_size, char *out_data, int out_size, unsigned long *total_out);

#endif
