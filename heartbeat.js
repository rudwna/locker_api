var config = require('./config');
var pg = require('pg');
var pg_constr = config.sfmt("postgres://{0}:{1}@{2}/{3}", config.db.client.username, config.db.client.password,
	config.db.host, config.db.name)
var can = require('socketcan');
var jwt = require('jsonwebtoken');
var sha1 = require('sha1');

// CAN
var can_ch = can.createRawChannel('can0', true);
can_ch.start();

var lockers_timeout = new Object;

pg.on('error', function(err, client) {
	console.error('Error D02: Database connection error', err);
	process.exit(1);
})

pg.connect(pg_constr, function(err, client, done) {
	if (err) {
		return console.error('error fetching client from pool', err);
	}

	client.query('select * from locker where logical_id is not null', function(err, result) {
		result.rows.forEach(function(locker) {
			lockers_timeout[locker.id] = {last_time: new Date().getTime(), is_alive: locker.is_alive};
		})
	})

	setInterval(function() {
		for (key_id in lockers_timeout) {
			if (new Date().getTime() - lockers_timeout[key_id].last_time > 2000 && lockers_timeout[key_id].is_alive == true) {
				console.log('#' + key_id + ' is dead');
				lockers_timeout[key_id].is_alive = false;
				client.query('update locker set is_alive=false where id=$1', [key_id]);
			}
		}
	}, 1000);

	can_ch.addListener('onMessage', function(msg) {
		var can_cmd = msg.id & 0x780;
		var locker_id = msg.id & 0x07F;
		if (can_cmd == 0x080) {
			// Heartbeat message
			if ('' + locker_id in lockers_timeout) {
				if (lockers_timeout[locker_id].is_alive != true) {
					client.query('update locker set is_alive=true where id=$1', [locker_id]);
					console.log('#' + locker_id + ' coming alive');
					lockers_timeout[locker_id].is_alive = true;
				}
				lockers_timeout[locker_id].last_time = new Date().getTime();
			}
		}
	});


});
