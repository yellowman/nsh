/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* What a statement does with the indented lines after it */
#define CT_LEAF		0	/* takes none */
#define CT_LINES	1	/* they are its children */
#define CT_NESTED	2	/* they are statements with children (rtable) */

/* How conftree_edit() changes the tree */
#define CE_SET		1	/* the line replaces the lines with its key */
#define CE_UNSET	2	/* the lines with this key go */
#define CE_ADD		3	/* the line is added, once */
#define CE_DEL		4	/* the line goes */
#define CE_LISTADD	5	/* the values join the line with their name */
#define CE_LISTDEL	6	/* the values leave it, and an empty line goes */
#define CE_BLOCK	7	/* the statement is there, at the top level */
#define CE_NOBLOCK	8	/* the statement and its lines go */
#define CE_RENAME	9	/* the statement reads line, with its lines */
#define CE_SEQ		10	/* the line follows the ordered block's lines */

/*
 * The key of a line, by which CE_SET and CE_UNSET find the lines they
 * replace: its first n words, after "no". With CK_ADDR, the last of them
 * is an address, without its "/prefixlen".
 */
#define CK_ADDR		0x100

/* What conftree_edit() returns, besides -1 */
#define CE_NOOP		0	/* the tree already said so */
#define CE_CHANGED	1

struct cnode;
struct cjournal;

struct cnode *conftree_read(char *, int (*)(char *), int (*)(char *));
struct cnode *conftree_fread(FILE *, char *, int (*)(char *), int (*)(char *));
struct cnode *conftree_mem(char *, size_t, char *, int (*)(char *),
    int (*)(char *));
void conftree_free(struct cnode *);
struct cnode *conftree_copy(struct cnode *);
int conftree_compare(FILE *, struct cnode *, struct cnode *);
int conftree_edit(struct cnode *, int, char *, char *, int);
int conftree_has(struct cnode *, char *);
char *conftree_stmt(struct cnode *, size_t);
char *conftree_line(struct cnode *, char *, char *, size_t);
int conftree_haskey(struct cnode *, char *, char *, int);
int conftree_write(FILE *, struct cnode *);

struct cjournal *cjournal_new(void);
int cjournal_add(struct cjournal *, int, char *, char *, int);
size_t cjournal_len(struct cjournal *);
int cjournal_replay(struct cjournal *, struct cnode *);
void cjournal_free(struct cjournal *);
