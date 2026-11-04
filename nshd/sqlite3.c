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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/limits.h>
#include <sqlite3.h>
#include "stringlist.h"
#include "externs.h"

int sq3simple(char *, StringList *);
static int sq3query(StringList *, const char *, ...);

void
db_create(void)
{
	/* create temporal tables (if they aren't already there) */
	if (db_create_table_rtables() < 0)
		printf("%% database rtables creation failed\n");
	if (db_create_table_flag_x("ctl") < 0)
		printf("%% database ctl creation failed\n");
	if (db_create_table_flag_x("dhcrelay") < 0)
		printf("%% database dhcrelay creation failed\n");
	if (db_create_table_flag_x("dhcrelay6") < 0)
		printf("%% database dhcrelay6 creation failed\n");
	if (db_create_table_flag_x("ipv6linklocal") < 0)
		printf("%% database ipv6linklocal creation failed\n");
	if (db_create_table_flag_x("lladdr") < 0)
		printf("%% database lladdr creation failed\n");
	if (db_create_table_flag_x("authkey") < 0)
		printf("%% database authkey creation failed\n");
	if (db_create_table_flag_x("nwkey") < 0)
		printf("%% database nwkey creation failed\n");
	if (db_create_table_flag_x("peerkey") < 0)
		printf("%% database peerkey creation failed\n");
	if (db_create_table_nameservers() < 0)
		printf("%% database nameservers creation failed\n");
	if (db_create_table_flag_x("pppoeipaddrmode") < 0)
		printf("%% database pppoeipaddrmode creation failed\n");
	if (db_create_table_flag_x("pin") < 0)
		printf("%% database pin creation failed\n");
	if (db_create_table_flag_x("wpakey") < 0)
		printf("%% database wpakey creation failed\n");
	if (db_create_table_flag_x("chan") < 0)
		printf("%% database chan creation failed\n");
	if (db_create_table_flag_x("joinkey") < 0)
		printf("%% database joinkey creation failed\n");
}

int
db_create_table_rtables(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS rtables (rtable INTEGER PRIMARY KEY, name TEXT)";
	return sq3simple(query, NULL);
}

int
db_create_table_nameservers(void)
{
	char query[]="CREATE TABLE IF NOT EXISTS nameservers (nameserver TEXT)";
	return sq3simple(query, NULL);
}

int
db_create_table_flag_x(char *name)
{
	return sq3query(NULL, "CREATE TABLE IF NOT EXISTS '%q' (ctl TEXT, "
	    "rtable INTEGER, flag INTEGER, data TEXT)", name);
}

int
db_insert_flag_x(char *name, char *ctl, int rtableid, int flag, char *data)
{
	return sq3query(NULL, "INSERT INTO '%q' VALUES('%q', %d, %d, '%q')",
	    name, ctl, rtableid, flag, data ? data : "");
}

int
db_insert_rtables(int rtableid, char *name)
{
	return sq3query(NULL, "INSERT INTO 'rtables' VALUES(%d, '%q')",
	    rtableid, name);
}

int
db_delete_rtables_rtable(int rtableid)
{
	return sq3query(NULL, "DELETE FROM 'rtables' WHERE rtable=%d",
	    rtableid);
}

int
db_insert_nameserver(char *nameserver)
{
	return sq3query(NULL, "INSERT OR REPLACE INTO 'nameservers' "
	    "VALUES('%q')", nameserver);
}

int
db_delete_flag_x_ctl(char *name, char *ctl, int rtable)
{
	return sq3query(NULL, "DELETE FROM '%q' WHERE ctl='%q' AND rtable=%d",
	    name, ctl, rtable);
}

int
db_delete_flag_x_ctl_data(char *name, char *ctl, char *data)
{
	return sq3query(NULL, "DELETE FROM '%q' WHERE ctl='%q' AND data='%q'",
	    name, ctl, data);
}

int
db_delete_nameservers(void)
{
	return sq3query(NULL, "DELETE FROM 'nameservers'");
}

int
db_select_flag_x_ctl_data(StringList *words, char *name, char *ctl, char *data)
{
	return sq3query(words, "SELECT data FROM '%q' WHERE ctl='%q' AND "
	    "data='%q'", name, ctl, data);
}

int
db_select_flag_x_ctl(StringList *words, char *name, char *ctl)
{
	return sq3query(words, "SELECT data FROM '%q' WHERE ctl='%q'", name,
	    ctl);
}

int
db_select_rtable_rtables(StringList *words)
{
	char query[]="SELECT rtable FROM rtables";
	return sq3simple(query, words);
}

int
db_select_rtables_rtable(StringList *words, int rtableid)
{
	return sq3query(words, "SELECT name FROM rtables WHERE rtable=%d",
	    rtableid);
}

int
db_select_flag_x_data_ctl_rtable(StringList *words, char *name, char *ctl, int rtableid)
{
	return sq3query(words, "SELECT data FROM '%q' WHERE ctl='%q' AND "
	    "rtable=%d", name, ctl, rtableid);
}

int
db_select_flag_x_dbflag_rtable(char *name, char *ctl, int rtableid)
{
	StringList	*words;
	int		rv;
	const char	*errmsg = NULL;

	words = sl_init();
	if ((rv = sq3query(words, "SELECT flag FROM '%q' WHERE ctl='%q' AND "
	    "rtable=%d", name, ctl, rtableid)) > 0) {
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
	return sq3simple(query, words);
}

int
db_select_name_rtable(StringList *words, int rtableid)
{
	return sq3query(words, "SELECT name FROM rtables WHERE rtable='%d'",
	    rtableid);
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

/*
 * sq3simple() for a query sqlite3_vmprintf() makes from fmt, so that %q
 * puts text in quotes, a quote in it doubled
 */
static int
sq3query(StringList *words, const char *fmt, ...)
{
	va_list		ap;
	char		*sql;
	int		rv;

	va_start(ap, fmt);
	sql = sqlite3_vmprintf(fmt, ap);
	va_end(ap);
	if (sql == NULL) {
		printf("%% sq3query: %s\n", strerror(ENOMEM));
		return -1;
	}
	rv = sq3simple(sql, words);
	sqlite3_free(sql);
	return rv;
}
