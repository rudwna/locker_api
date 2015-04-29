var restify = require('restify');
var pg = require('pg');
var pg_constr = "postgres://locker_admin:password@192.168.100.252/locker_api";
var can = require('socketcan');
var rjwt = require('restify-jwt');
var jwt = require('jsonwebtoken');
var sha1 = require('sha1');
var server = restify.createServer({
	name: 'locker_api'
});
var io = require('socket.io').listen(server.server);

// jwt secret key
var secret = '516f51c22688937cbc71fb599c5b9896e10bc531';

restify.CORS.ALLOW_HEADERS.push('authorization');
server.use(restify.CORS());
server.use(restify.acceptParser(server.acceptable));
server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(rjwt({ secret: secret }).unless( {path: ['/admin/login', '/login', '/test', '/qx']} ));

// CAN
var can_ch = can.createRawChannel('can0', true);
can_ch.start();

server.listen(8081, function () {
	console.log('%s listening at %s', server.name, server.url);
});


// socket.io
io.sockets.on('connection', function(socket) {
	console.log('user connected');
})



pg.connect(pg_constr, function(err, client, done) {
	if (err) {
		return console.error('error fetching client from pool', err);
	}

	server.post('/admin/login', function(req, res, next) {
		var username = req.params.username || '';
		var password = req.params.password || '';
		if (username == '' || password == '') {
			res.send(401, {code: 'emptyuserpassword', message: 'ชื่อผู้ใช้หรือรหัสผ่านเป็นค่าว่าง'});
		}

		client.query('select id from locker_user where username = $1 and password = $2 and is_admin = true', [username, sha1(password)], function(err, result) {
			if (err) {
				throw err;
			}

			if (result.rows.length == 0) {
				res.send(401, {code: 'invaliduserpassword', message:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'});
			}

			var profile = {
				id: result.rows[0].id,
				user: username,
				admin: true
			};

			var token = jwt.sign(profile, secret);
			res.json({ token: token });
		})
	});

	server.get('/history', function(req, res, next) {
		var locker_id = req.params['locker_id'];
		var user_id = req.params['user_id'];
		var page = req.params['page'] || 0;

		client.query("select a.id, a.created, a.state, a.reservation_id, l.logical_id from activity a, reservation r, locker l \
			where a.reservation_id in (select r.id from reservation r where (r.personal_id = $1 or $1 is null) and (r.locker_id = $2 or $2 is null) order by id desc limit 5 offset $3) \
				and a.reservation_id = r.id and r.locker_id = l.id \
			order by a.id asc", [user_id, locker_id, 5*page], function(err, result) {
			if (err) {
				return;
			}
			res.send(result.rows);
		})
	});

	server.get('/lockers', function(req, res, next) {
		client.query('select * from locker where logical_id is not null order by logical_id asc', function(err, result) {
			if (err) {
				console.log(err);
				return;
			}
			res.send(result.rows);
		});
		return next();
	});

	server.get('/lockers/unassigned', function(req, res, next) {
		client.query('select * from locker where logical_id is null order by id', function(err, result) {
			if (err) throw err;

			res.send(result.rows);
		});

		return next();
	});

	server.post('/lockers/assign', function(req, res, next) {
		var err_lockers = [];

		function conclude() {
			if (err_lockers.length > 0) {
				res.send(400, {code: 'xxx', message: 'ไม่สามารถกำหนดค่าล็อกเกอร์หมายเลข ' + err_lockers.join(', ')});
			} else {
				res.send(200);
			}
		}

		req.params.lockers.forEach(function(locker, index) {
			client.query('update locker set logical_id=$1, configured_on=now() where id=$2', [locker.assign_no, locker.id], function(err, result) {
				if (err) {
					err_lockers.push(locker.assign_no);
				} else {
					var confd = { id: 0x200 + locker.id, ext: false, data: new Buffer([])};
					can_ch.send(confd);
				}

				if (index+1 == req.params.lockers.length) {
					conclude();
				}
			});
		});
	});

	server.get('/settings', function(req, res, next) {
		client.query('select * from settings', function(err, result) {
			if (err) throw err;
			res.send(result.rows);
		});

		return next();
	});

	server.put('/settings', function(req, res, next) {
		client.query("update settings set value=$1 where name='reserve_timeout'", [req.params.reserve_timeout], function(err, result) {
			if (err) {
				res.send(400, {code: 'xxx', message: err.toString()});
			} else {
				res.send(200);
			}
		});


		// var err_settings = [];

		// function conclude() {
		// 	if (err_settings.length > 0) {
		// 		res.send(400, {code: 'xxx', message: 'ไม่สามารถกำหนดค่า ' + err_settings.join(', ')});
		// 	} else {
		// 		res.send(200);
		// 	}
		// }

		// req.params.settings.forEach(function(setting, index) {
		// 	client.query('update setting set value=$1 where name=$2', [setting.value, setting.name], function(err, result) {
		// 		if (err) {
		// 			err_settings.push(setting.name);
		// 		}
		// 		if (index+1 == req.params.settings.length) {
		// 			conclude();
		// 		}
		// 	});
		// });
	});

	server.post('/lockers/:logical_id/clear_no', function(req, res, next) {
		var logical_id = req.params['logical_id'];

		client.query('select id, state from locker where is_alive=false and logical_id=$1', [logical_id], function(err, result) {
			var locker_id = result.rows[0].id;
			client.query('update locker set logical_id=NULL, configured_on=NULL where id=$1', [locker_id], function(err) {
				if (err) throw err;
				res.send(200);
			});
		});
	});

	// This method is not to be used by normal user
	// user'll typically open and close locker by RFID authorization
	// which sen CAN message the controller
	server.post('lockers/:logical_id/open', function(req, res) {
		var logical_id = req.params['logical_id'];

		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				res.send(400, { code: 'R002', message: 'สถานะในการเปิดไม่ถูกต้อง' });
			} else {
				client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, result) {
					if (err) throw err;
					console.log(result.rows);

					if (!result.rows[0].is_activated) {
						client.query("UPDATE reservation SET is_activated = 't' WHERE id = $1", [result.rows[0].id]);
					}

					client.query("UPDATE locker SET state = 2 WHERE id=$1", [locker_id], function(err, result) {
						// TODO: catch err
						if (err) throw err;
						// console.log('locker ' + locker_id + ' opened');
						res.send(200);

						var canmsg = { id: 0x380 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
					});

				});
			}
		});
		// return next();
	});

	// This method is not to be used by normal user
	// user'll typically open and close locker by RFID authorization
	// which sen CAN message the controller
	server.post('lockers/:logical_id/close', function(req, res) {
		var logical_id = req.params['logical_id'];
		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id = $1)", [locker_id], function(err, result) {
				if (err) throw err;

				if (2 != state) {
					res.send(400, {'code': 'R003', 'message': 'สถานะในการปิดไม่ถูกต้อง'});
				} else {
					client.query("UPDATE locker SET state = 3 WHERE id=$1", [locker_id], function(err, result) {
						if (err) throw err;

						console.log('locker ' + locker_id + ' closed');
						res.send(200);

						var canmsg = { id: 0x400 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
					});
				}

			});
		});
		// return next();
	});

	server.post('lockers/:logical_id/release', function(req, res) {
		var logical_id = req.params['logical_id'];
		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			if (err) throw err;
			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				res.send(400, { code: 'R004', message: 'สถานะในการเลิกใช้งานไม่ถูกต้อง' });
			} else {
				// conn.query("SELECT count(*) as count FROM reservation WHERE id IN (select max(id) from reservation group by locker_id) and personal_id=? group by personal_id", [personal_id], function(err, rows, result) {
				// TODO: using dynamic id from RFID card
				client.query("SELECT id FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, rows, result) {
					// TODO: catch err
					if (err) throw err;

					client.query("UPDATE locker SET state = 4 WHERE id = $1", [locker_id], function(err, result) {
						// TODO: catch err
						if (err) throw err;

						res.send(200);

						io.sockets.emit('released', locker_id);
						
						var canmsg = { id: 0x480 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
					});
				});
			}
		});
		// return next();
	});


	// pgsql LISTEN/NOTIFY
	client.on('notification', function(msg) {
		// console.log('notification');
		// console.log(msg);
		if (msg.channel == 'locker_is_alive_update') {
			var payload = msg.payload.split(',');
			if (payload[1] == 'true') {
				console.log('alive ' + payload[0]);
				io.sockets.emit('alive', payload[0]);
			} else if (payload[1] == 'false') {
				console.log('dead ' + payload[0]);
				io.sockets.emit('dead', payload[0]);
			}
		} else if (msg.channel == 'locker_state_update') {
			var payload = msg.payload.split(',');
			if (payload[2] == '0') {
				io.sockets.emit('free', payload[0] + ',' + payload[1] + ',' + payload[3]);
			} else if (payload[2] == '1') {
				io.sockets.emit('reserved', payload[0] + ',' + payload[1]);
			}
		}
	});

	client.query('LISTEN locker_is_alive_update');
	client.query('LISTEN locker_state_update');

});

