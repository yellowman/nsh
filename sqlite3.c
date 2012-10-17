/*
 * Copyright (c) 2012 Chris Cappuccio <chris@nmedia.net>
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "stringlist.h"
#include "externs.h"

int sq3simple(char *, StringList *);

#define QSZ 512 /* maximum query size */

int
db_create_table_rtables(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS rtables (rtable INTEGER PRIMARY KEY,name TEXT NOT NULL)";
	return(sq3simple(query, NULL));
}

int
db_create_table_daemons(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS daemons (daemon TEXT,rtable INTEGER,configfile TEXT)";
	return(sq3simple(query, NULL));
}

int
db_insert_daemons(char *daemon, int rtableid, char *configfile)
{
	char		query[QSZ];

	snprintf(query, QSZ, "INSERT INTO 'daemons' VALUES('%s', %d, '%s')", daemon, rtableid, configfile);
	return(sq3simple(query, NULL));
}

int
db_insert_rtables(int rtableid, char *name)
{
	char		query[QSZ];

	snprintf(query, QSZ, "INSERT INTO 'rtables' VALUES(%d, '%s')", rtableid, name);
	return(sq3simple(query, NULL));
}

int
db_delete_rtables_rtable(int rtableid)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM 'rtables' WHERE rtable='%d'", rtableid);
	return(sq3simple(query, NULL));
}

int
db_delete_daemons_daemon(char *daemon)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM 'daemons' WHERE daemon='%s'", daemon);
	return(sq3simple(query, NULL));
}

int
db_select_rtable_rtables(StringList *words)
{
	char query[]="SELECT rtable FROM rtables";
	return(sq3simple(query, words));
}

int
db_select_rtables_rtable(StringList *words, int rtableid)
{
	char		query[QSZ];

	snprintf(query, QSZ, "SELECT * FROM rtables WHERE rtable='%d'", rtableid);
	return(sq3simple(query,words));
}

int
db_select_daemon_rtable(StringList *words, int rtableid)
{
	char            query[QSZ];

	snprintf(query, QSZ, "SELECT daemon FROM daemons WHERE rtable='%d'", rtableid);
	return(sq3simple(query, words));
}

int
db_select_name_rtable(StringList *words, int rtableid)
{
	char		query[QSZ];

	snprintf(query, QSZ, "SELECT name FROM rtables WHERE rtable='%d'", rtableid);
	return(sq3simple(query, words));
}

/* simple query execution, dump results straight into words */
int
sq3simple(char *sql, StringList *words)
{
	sqlite3		*db;
	sqlite3_stmt	*stmt;
	char		*result, *new = NULL;
	int		rv, len, tlen = 0;

	if (sqlite3_open(SQ3DBFILE, &db)) {
		printf("%% database file open failed: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
	    != SQLITE_OK) {
		printf("%% sqlite3_prepare_v2 failed: %s (%s)\n",
		    sqlite3_errmsg(db), sql);
		return -1;
	}

	while ((rv = sqlite3_step(stmt)) == SQLITE_ROW) {
		result = (char *)sqlite3_column_text(stmt, 0);
		len = strlen(result) + 1;
		if ((new = malloc(len)) == NULL) {
			printf("%% sq3simple: malloc failed\n");
			break;
		}
		tlen =+ len;
		strlcpy(new, result, len);
		sl_add(words, new);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if (rv != SQLITE_DONE) {
		printf("%% sq3simple: error: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	return tlen;
}
