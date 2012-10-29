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

#define QSZ 1024 /* maximum query text size */

int
db_create_table_rtables(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS rtables (rtable INTEGER PRIMARY KEY, name TEXT)";
	return(sq3simple(query, NULL));
}

int
db_create_table_flag_x(char *name)
{
	char		query[QSZ];

	snprintf(query, QSZ, "CREATE TABLE IF NOT EXISTS %s (ctl TEXT, rtable INTEGER, flag INTEGER,"
	    "data TEXT)", name);
	return(sq3simple(query, NULL));
}

int
db_insert_flag_x(char *name, char *ctl, int rtableid, int flag, char *data)
{
	char		query[QSZ];

	snprintf(query, QSZ, "INSERT INTO '%s' VALUES('%s', %d, %d, '%s')",
	    name, ctl, rtableid, flag, data);
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

	snprintf(query, QSZ, "DELETE FROM 'rtables' WHERE rtable=%d", rtableid);
	return(sq3simple(query, NULL));
}

int
db_delete_flag_x_ctl(char *name, char *ctl)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM '%s' WHERE ctl='%s' AND rtable=%d", name, ctl, cli_rtable);
	return(sq3simple(query, NULL));
}

int
db_delete_flag_x_ctl_data(char *name, char *ctl, char *data)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM '%s' WHERE ctl='%s' AND data='%s'", name, ctl, data);
	return(sq3simple(query, NULL));
}

int
db_select_flag_x_ctl_data(StringList *words, char *name, char *ctl, char *data)
{
	char		query[QSZ];

	snprintf(query, QSZ, "SELECT data FROM '%s' WHERE ctl='%s' AND data='%s'", name, ctl, data);
	return(sq3simple(query, words));
}

int
db_select_flag_x_ctl(StringList *words, char *name, char *ctl)
{
	char		query [QSZ];

	snprintf(query, QSZ, "SELECT data FROM '%s' WHERE ctl='%s'", name, ctl);
	return(sq3simple(query, words));
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

	snprintf(query, QSZ, "SELECT name FROM rtables WHERE rtable=%d", rtableid);
	return(sq3simple(query,words));
}

int
db_select_flag_x_ctl_rtable(StringList *words, char *name, int rtableid)
{
	char            query[QSZ];

	snprintf(query, QSZ, "SELECT ctl FROM %s WHERE rtable=%d", name, rtableid);
	return(sq3simple(query, words));
}

int
db_select_flag_x_data_ctl_rtable(StringList *words, char *name, char *ctl, int rtableid)
{
	char		query[QSZ];

	snprintf(query, QSZ, "SELECT data FROM %s WHERE ctl='%s' AND rtable=%d",
	    name, ctl, rtableid);
	return(sq3simple(query, words));
}

int
db_select_flag_x_dbflag_rtable(char *name, char *ctl, int rtableid)
{
	StringList	*words;
	char		query[QSZ];
	int		rv;

	snprintf(query, QSZ, "SELECT flag FROM %s WHERE ctl='%s' AND rtable=%d",
	    name, ctl, rtableid);
	words = sl_init();
	if((rv = sq3simple(query, words)) > 0)
		rv = atoi(words->sl_str[0]);
	sl_free(words, 1);

	return rv;
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
