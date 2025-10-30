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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/limits.h>
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
db_create_table_nameservers(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS nameservers (nameserver TEXT)";
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
	    name, ctl, rtableid, flag, data ? data : "");
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
db_insert_nameserver(char *nameserver)
{
	char		query[QSZ];

	snprintf(query, QSZ, "INSERT OR REPLACE INTO 'nameservers' VALUES('%s')",
	    nameserver);
	return(sq3simple(query, NULL));
}

int
db_delete_flag_x_ctl(char *name, char *ctl, int rtable)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM '%s' WHERE ctl='%s' AND rtable=%d", name, ctl, rtable);
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
db_delete_nameservers(void)
{
	char		query[QSZ];

	snprintf(query, QSZ, "DELETE FROM 'nameservers'");
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
	const char	*errmsg = NULL;

	snprintf(query, QSZ, "SELECT flag FROM %s WHERE ctl='%s' AND rtable=%d",
	    name, ctl, rtableid);
	words = sl_init();
	if((rv = sq3simple(query, words)) > 0) {
		rv = strtonum(words->sl_str[0], INT_MIN, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% db_select_flag_x_dbflag_rtable %s: %s\n", 
                            words->sl_str[0], errmsg);
			rv = -1;
                }
	}

	sl_free(words, 1);

	return rv;
}

int
db_select_nameservers(StringList *words)
{
	char query[]="SELECT nameserver FROM nameservers";
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
	sqlite3		*db = NULL;
	sqlite3_stmt	*stmt;
	char		*result, *new = NULL;
	int		rv, tlen = 0;

	if (sqlite3_open(SQ3DBFILE, &db)) {
		printf("%% database file open failed: %s\n",
		    db ? sqlite3_errmsg(db) : strerror(ENOMEM));
		tlen = -1;
		goto done;
	}
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)
	    != SQLITE_OK) {
		printf("%% sqlite3_prepare_v2 failed: %s (%s)\n",
		    sqlite3_errmsg(db), sql);
		tlen = -1;
		goto done;
	}

	while ((rv = sqlite3_step(stmt)) == SQLITE_ROW) {
		result = (char *)sqlite3_column_text(stmt, 0);
		new = strdup(result);
		if (new == NULL) {
			printf("%% sq3simple: strdup failed: %s\n",
			    strerror(errno));
			break;
		}
		tlen += strlen(new) + 1;
		sl_add(words, new);
	}

	if (rv != SQLITE_DONE) {
		printf("%% sqlite3_step: %s\n", sqlite3_errstr(rv));
		tlen = -1;
	}

	rv = sqlite3_finalize(stmt);
	if (rv != SQLITE_OK) {
		printf("%% sqlite3_finalize: %s\n", sqlite3_errstr(rv));
		tlen = -1;
	}
done:
	if (db)
		sqlite3_close(db);

	return tlen;
}
