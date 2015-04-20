#!/usr/bin/env node

// Requirements
var pg = require('pg');
var fs = require('fs');
var sys = require('sys');
var readline = require('./readline');
var toPatt = new RegExp("to=<([^>]*)>");
var postfixPatt = new RegExp("postfix/[a-z]*\[[0-9]*\]: ([^:]*):");
var saslUsernamePatt = new RegExp("sasl_username=(.*)");
var saslUsers = {};
var transactions = {}
var dbConnectObj = {'user': 'mailrat',
		    'database': 'mailrat',
		    'password': 'SX4t8rhr5o3w',
		    'port': 5432,
		    'host': 'localhost'};

var lineFunc = function(line) {
    // First see if it's a line we even _might_ care about:
    var qidvec = postfixPatt.exec(line);
    if (qidvec != null && qidvec.length > 1) {
	// It is, so extract the queue ID:
	var qid = qidvec[1];
	// See if we have a transaction for that queue ID, which would
	// mean that this is an authenticated submission
	if (transactions.hasOwnProperty(qid)) {
	    // We do, so see if this line has a to=<...> string in it.
	    var tovec = toPatt.exec(line);
	    if (tovec != null && tovec.length > 1) {
		var to = tovec[1];
		// It does, so see if this user already has
		// that email address on its friends list.
		var user = transactions[qid];

		if (saslUsers.hasOwnProperty(user)) {
		    userdict = saslUsers[user];
		    // If not, add it.
		    if (!userdict.hasOwnProperty(to)) {
			userdict[to] = true;}}}
	} else {
	    // Otherwise see if this is a sasl login line,
	    // meaning that this is the start of an
	    // authenticated submission log (which would then
	    // trigger all the above fun and games).
	    var uservec = saslUsernamePatt.exec(line);
	    if (uservec != null && uservec.length > 1) {
		var user = uservec[1];
		// It is, so see if we've already seen this user.
		if (!saslUsers.hasOwnProperty(user)) {
		    // We haven't, so add the user.
		    saslUsers[user] = {};}
		// In any case, mark the Queue ID as being a
		// transaction for the user that we just
		// identified.
		transactions[qid] = user;}}}
    return false;}

fs.readdirSync('/var/log').forEach(function(filename) {
    if (filename.match('^mail.log.[0-9]')) {
	readline.readlines('/var/log/' + filename, lineFunc);
    }});

// Stuff all this info into the database.
for (var key in saslUsers) {
    sys.print(key + ":");
    if (saslUsers.hasOwnProperty(key)) {
	var userdict = saslUsers[key];
	for (var ukey in userdict) {
	    var closure = function(user, addr) {
		pg.connect(dbConnectObj, function(error, client, done) {
		    if (error != null) {
			sys.print("Can't connect: " + error.toString() + "\n");
		    } else {
			// For debugging purposes, dump what we just
			// learned.
			sys.print(user + ": " + addr + "\n");
			var q = "SELECT associate_if_missing($1, $2)"
			client.query(q, [user, addr], function(err, res) {
			    if (err != null) {
				sys.print("can't update: " +
					  err.toString() + "\n");
			    } else {
				client.query("COMMIT WORK", [], function(e,r) {
				    sys.print("calling done...\n");
				    done();
				    sys.print("done calling done\n");
				});}});}});};
	    closure(key, ukey);}}}
