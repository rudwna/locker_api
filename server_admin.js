var config = require('./config');
var restify = require('restify');
var pg = require('pg');
var pg_constr = config.sfmt("postgres://{0}:{1}@{2}/{3}", config.db.client.username, config.db.client.password,
	config.db.host, config.db.name)
var can = require('socketcan');
var rjwt = require('restify-jwt');
var jwt = require('jsonwebtoken');
var sha1 = require('sha1');
var server = restify.createServer({
	name: 'locker_api'
});
var io = require('socket.io').listen(server.server);

restify.CORS.ALLOW_HEADERS.push('authorization');
server.use(restify.CORS());
server.use(restify.acceptParser(server.acceptable));
server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(rjwt({ secret: config.jwt.secret }).unless( {path: ['/admin/login']} ));

// CAN
var can_ch = can.createRawChannel('can0', true);
can_ch.start();

server.listen(config.service.client.port, function () {
	console.log('%s listening at %s', server.name, server.url);
});

// socket.io
io.sockets.on('connection', function(socket) {
	console.log('user connected');
})

pg.connect(pg_constr, function(err, client, done) {
	if (err) {
		console.error('Error A00X: Error creating database client. Please check database connection is working.', err);
		process.exit(1);
	}

	server.post('/admin/login', function(req, res, next) {
		var username = req.params.username || '';
		var password = req.params.password || '';

		// Test for empty value
		if (username == '' || password == '') {
			res.send(401, {code: 'emptyuserpassword', message: 'ชื่อผู้ใช้หรือรหัสผ่านเป็นค่าว่าง'});
		}

		client.query('select id from locker_user where username = $1 and password = $2 and is_admin = true', [username, sha1(password)], function(err, result) {
			if (err) {
				console.log('Error D00X: Error getting user data from database');
				return res.send(401, {code: 'L00X', message: 'ไม่สามารถรับข้อมูลลผู้ใช้จากฐานข้อมูลได้'});
			}

			if (result.rows.length == 0) {
				console.log('Error D00X: User #' + username + ' not found');
				return res.send(401, {code: 'L00X', message:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'});
			}

			var profile = {
				id: result.rows[0].id,
				user: username,
				admin: true
			};

			res.json({ token: token });
			var token = jwt.sign(profile, config.jwt.secret);
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
				console.log('Error D00X: Cannot get user\'s usage history');
				return res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกดูประวัติการใช้งานได้'});
			}
			res.send(result.rows);
		})
	});

	server.get('/lockers', function(req, res, next) {
		client.query('select * from locker where logical_id is not null order by logical_id asc', function(err, result) {
			if (err) {
				console.log('Error D00X: Cannot get locker data from database');
				return res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้'});
			}

			res.send(result.rows);
		});
		return next();
	});

	server.get('/lockers/unassigned', function(req, res, next) {
		client.query('select * from locker where logical_id is null order by id', function(err, result) {
			if (err) {
				console.log('Error D00X: Cannot get locker data from database');
				return res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้'});
			}

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
					console.log('Error D00X: Cannot assign locker number')
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
			if (err) {
				console.log('Error D00X: Cannot get system settings')
				res.send(400, {code: 'D00X', message: 'ไม่สามารถเรียกข้อมูลการตั้งค่า'});

			}
			res.send(result.rows);
		});

		return next();
	});

	server.put('/settings', function(req, res, next) {
		client.query("update settings set value=$1 where name='reserve_timeout'", [req.params.reserve_timeout], function(err, result) {
			if (err) {
				console.log('Error D00X: Cannot update system settings')
				res.send(400, {code: 'D00X', message: err.toString()});
			} else {
				res.send(200);
			}
		});

	});

	server.post('/lockers/:logical_id/clear_no', function(req, res, next) {
		var logical_id = req.params['logical_id'];

		client.query('select id, state from locker where is_alive=false and logical_id=$1', [logical_id], function(err, result) {
			if (err) {
					console.log('Error D00X: Cannot get locker data from database')
					res.send(400, {code: 'D00X', message: 'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้'});
			}
			var locker_id = result.rows[0].id;
			client.query('update locker set logical_id=NULL, configured_on=NULL where id=$1', [locker_id], function(err) {
				if (err) {
					console.log('Error D00X: Cannot clear locker number')
					res.send(400, {code: 'D00X', message: 'ไม่สามารถล่างหมายเลขล็อกเกอร์ได้'});
				}
				res.send(200);
			});
		});
	});

	// Method to override and open all lockers
	server.post('lockers/all/open', function(req, res) {
		var canmsg = { id: 0x500, ext: false, data: new Buffer([]) };
		can_ch.send(canmsg);
		res.send(200);
	})

	// Method to open specific locker
	server.post('lockers/:logical_id/open', function(req, res) {
		var logical_id = req.params['logical_id'];

		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			if (err) {
				console.log('Error D00X: Cannot get locker data from database')
				res.send(400, {code: 'D00X', message: 'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้'});
			}

			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				console.log('Error D00X: Invalid locker state for opening')
				res.send(400, { code: 'R002', message: 'สถานะในการเปิดไม่ถูกต้อง' });
			} else {
				client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, result) {
					if (err) {
						console.log('Error D00X: Cannot get reservation data from database')
						res.send(400, {code: 'D00X', message: 'ไม่สามารถเรียกข้อมูลลการจองได้'});
					}

					// non-trivial
					// error not handled
					// TODO: log the error
					if (!result.rows[0].is_activated) {
						client.query("UPDATE reservation SET is_activated = 't' WHERE id = $1", [result.rows[0].id]);
					}

					// update locker state to 'open'
					client.query("UPDATE locker SET state = 2 WHERE id=$1", [locker_id], function(err, result) {
						if (err) {
							// note: this invalidate the flow of system
							// if is_activated is set but the locker state is not updated
							console.log('Error D00X: Cannot update locker state');
							res.send(401, { code: 'R002', message: 'ไม่สามารถเปลี่ยนสถานะล็อกเกอร์ได้' });
						}
						console.log('##' + locker_id + ' opened');
						res.send(200);

						var canmsg = { id: 0x380 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
					});

				});
			}
		});
		// return next();
	});


	server.post('lockers/:logical_id/release', function(req, res) {
		var logical_id = req.params['logical_id'];
		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			if (err) {
				console.log('Error D00X: Cannot get locker data from database');
				return res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้ ' + logical_id + ' ได้'});
			}

			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				console.log('Error D00X: Invlid locker state change');
				return res.send(401, { code: 'L00X', message: 'สถานะในการเลิกใช้งานไม่ถูกต้อง' });
			} else {
				// conn.query("SELECT count(*) as count FROM reservation WHERE id IN (select max(id) from reservation group by locker_id) and personal_id=? group by personal_id", [personal_id], function(err, rows, result) {
				// TODO: using dynamic id from RFID card
				client.query("SELECT id FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, rows, result) {
					if (err) {
						console.log('Error D00X: No such reservation found');
						return res.send(401, { code: 'L00X', message: 'ไม่พบการจองที่ต้องการ' });
					}

					client.query("UPDATE locker SET state = 4 WHERE id = $1", [locker_id], function(err, result) {
						if (err) {
							console.log('Error D00X: Cannot update locker state');
							return res.send(401, { code: 'L00X', message: 'ไม่สามารถเปลี่ยนสถานะล็อกเกอร์ได้' });
						}

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

