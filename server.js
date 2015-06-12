var config = require('./config');
var restify = require('restify');
var pg = require('pg');
var pg_constr = config.sfmt("postgres://{0}:{1}@{2}/{3}", config.db.client.username, config.db.client.password,
	config.db.host, config.db.name);
var can = require('socketcan');
var rjwt = require('restify-jwt');
var jwt = require('jsonwebtoken');
var sha1 = require('sha1');
var server = restify.createServer({
	name: 'locker_api'
});
var io = require('socket.io').listen(server.server);
var log_ts = require('log-timestamp')(function() { return '[' + new Date().toString() + ']' });

restify.CORS.ALLOW_HEADERS.push('authorization');
server.use(restify.CORS());
server.use(restify.acceptParser(server.acceptable));
server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(rjwt({ secret: config.jwt.secret }).unless( {path: ['/login']} ));

// CAN
var can_ch = can.createRawChannel('can0', true);
can_ch.start();

server.listen(config.service.client_port, function () {
	console.log('%s listening at %s', server.name, server.url);
});


// socket.io
io.sockets.on('connection', function(socket) {
	console.log('user connected');
})

pg.connect(pg_constr, function(err, pgc, done) {
	if (err) {
		console.error('Error A00X: Error creating database client. Please check database connection is working.', err);
		process.exit(1);
	}

	can_ch.addListener('onMessage', function(msg) {
		var can_cmd = msg.id & 0x700;
		var locker_id = msg.id & 0x0FF;
		if (can_cmd == 0x100) {
			// locker registration request

			// check if msg.data[0] (LID) is in database
			pgc.query('select id, logical_id, state from locker where id = $1', [locker_id], function(err, result) {
				var locker = result.rows[0];

				if (err) {
					console.error('Error D00X: Error creating database client. Please check database connection is working.', err);
					return;
				}

				// if there's no data, create new row for it
				if (result.rows[0] === undefined) {
					pgc.query('insert into locker(id, state) values ($1, $2)', [locker_id, 0], function(err, result) {
						if (err) {
							console.error('Error D00X: Error creating database client. Please check database connection is working.', err);
							return;
						} else {
							var regd = { id: 0x180 + locker_id, ext: false, data: new Buffer([]) };
							can_ch.send(regd);
						}
					});
				} else {
					// locker data exists
					// now determine if it's configured or not
					console.log('#' + result.rows[0] + ' request for registration');
					if (locker_id == locker.id) {

						if (result.rows[0].logical_id == null) {
							// if the locker is not configured

							// send regd message to locker
							console.log('#' + result.rows[0] + ' registered but not configured');
							var regd = { id: 0x180 + locker_id, ext: false, data: new Buffer([])};
							can_ch.send(regd);
						} else {
							// if the locker is configured

							// get last locker's state
							var state = result.rows[0].state;

							// remap reserved/opened to normal reserved state on LU
							if (3 == state) state = 1;

							console.log('#' + result.rows[0] + ' registered, resume to last state');
							var confd = { id: 0x200 + locker_id, ext: false, data: new Buffer([state])};
							can_ch.send(confd);
						}
						
					}
				}
			});
		} else if (msg.id == 0x300) {
			// RFID reader's message when card present

			var user_id = msg.data.toString('hex');

			// query locker that reserved by card holder
			var query = 	"select id from locker where id = ( \
								select locker_id from reservation where id = ( \
									select max(id) from reservation where personal_id = ( \
										select id from locker_user where username = $1 \
									) \
								group by locker_id \
								) \
							) \
							and (state = 1 or state = 3)";


			pgc.query(query, [user_id], function(err, result_i) {

				if (err) {
					console.error('Error D00X: Cannot get locker data from database', err);
					return;
				}

				if (undefined === result_i.rows[0]) {
					console.error('Error R00X: Cannot find reserved locker that match card holder\'s ID');
					return;
				}

				// Test and turn on is_activated for reservation
				var locker_id = result_i.rows[0].id;
				pgc.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, result_ii) {
					if (err) {
						console.error('Error R00X: Cannot query reservation data');
						return;
					}

					if (!result_ii.rows[0].is_activated) {
						pgc.query("UPDATE reservation SET is_activated = 't' WHERE id = $1", [result_ii.rows[0].id]);
					}

					// Update is_activated
					// TODO: merge this to use outer query instead
					pgc.query("UPDATE locker SET state = 2 WHERE id=$1", [locker_id], function(err, result_iii) {
						if (err) {
							console.error('Error D00X: Cannot update reservation data');
							return;
						}

						var canmsg = { id: 0x380 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
						console.log(new Date().toString() + ' Info: # ' + locker_id + ' opened by user #' + req.user.id + ',' + req.user.username);
					});

				});
			})

		} else if (can_cmd == 0x400) {
			// Locker closed event
			pgc.query('select id, logical_id, state from locker where state=2 and id=$1', [locker_id], function(err, result) {

				if (err) {
					console.error('Error D00X: Cannot query locker data');
					return;					
				}

				if (result.rows.length == 0) {
					console.error('Error D00X: Empty locker data while in closing event');
					return;
				} else {
					var locker = result.rows[0];
				}

				// select latest reservation of locker
				pgc.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id = $1)", [locker_id], function(err, result_i) {
					if (err) {
						console.error('Error D00X: Cannot get reservation data');
						return;
					}

					if (result_i.rows.length == 0) {
						console.error('Error D00X: Empty locker data while in closing event');
						return;
					}

					// console.log('s'+ locker.state);

					if (2 != locker.state) {
						console.error('Error L00X: Invalid locker\'s state for closing');
						return;
					} else {
						pgc.query("UPDATE locker SET state = 3 WHERE id=$1", [locker_id], function(err, result) {
							if (err) {
								console.error('Error D00X: Error updating locker data');
								return;
							}

							console.log('Info: # ' + locker_id + ' closed by user #' + req.user.id + ',' + req.user.username);
						});
					}
				});
			});
		}
	})

	server.post('/login', function(req, res, next) {
		var username = req.params.username || '';
		var password = req.params.password || '';

		// Test for empty value
		if (username == '' || password == '') {
			res.send(401, {code: 'L00X', message: 'ชื่อผู้ใช้หรือรหัสผ่านเป็นค่าว่าง'});
			return next();
		}

		pgc.query('select id from locker_user where username = $1 and password = $2', [username, sha1(password)], function(err, result) {
			if (err) {
				console.error('Error D00X: Error getting user data from database');
				res.send(401, {code: 'L00X', message: 'ไม่สามารถรับข้อมูลลผู้ใช้จากฐานข้อมูลได้'});
				return next();
			}

			if (result.rows.length == 0) {
				console.error('Error D00X: User #' + username + ' not found');
				res.send(401, {code: 'L00X', message:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'});
				return next();
			}

			var profile = {
				id: result.rows[0].id,
				username: username
			};

			var token = jwt.sign(profile, config.jwt.secret);
			res.json({ token: token });
			console.log('Info: login success from user u#' + result.rows[0].id + ',' + username);
			return next();
		})
	});

	server.get('/user/is_reserved', function(req, res, next) {
		var user_id = req.user.id;

		pgc.query('select l.logical_id from reservation r, locker l where r.id in ( \
			select max(id) from reservation group by locker_id \
			) and l.state > 0 and personal_id = $1 and l.id = r.locker_id', [user_id], function(err, result) {
			if (err) {
				console.error('Error D00X: Cannot get user\'s reservation state');
				res.send(401, {code: 'L00X', message:'ไม่สามารถตรวจสอบสถานะการจองของผู้ใช้ได้'});
				return next();
			}

			res.send({ is_reserved: result.rows.length > 0 ? result.rows[0].logical_id : 'false'});
			return next();
		})
	});

	server.get('/history', function(req, res, next) {
		var user_id = req.user.id;
		var page = req.params['page'] || 0;

		pgc.query("select a.id, a.created, a.state, a.reservation_id, l.logical_id from activity a, reservation r, locker l \
			where a.reservation_id in (select r.id from reservation r where r.personal_id = $1 order by id desc limit 5 offset $2) \
				and a.reservation_id = r.id and r.locker_id = l.id \
			order by a.id asc", [user_id, 5*page], function(err, result) {
			if (err) {
				console.error('Error D00X: Cannot get user\'s usage history');
				res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกดูประวัติการใช้งานได้'});
				return next();
			}
			res.send(result.rows);
			return next();
		})
	});

	server.get('/lockers', function(req, res, next) {
		pgc.query('select * from locker where logical_id is not null order by logical_id asc', function(err, result) {
			if (err) {
				console.error('Error D00X: Cannot get locker data from database');
				res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้'});
				return next();
			}

			res.send(result.rows);
			return next();
		});
	});

	server.post('/lockers/:logical_id/reserve', function(req, res) {
		var user_id = req.user.id;
		var logical_id = req.params['logical_id'];

		pgc.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			if (err) {
				console.error('Error D00X: Cannot get locker data from database');
				res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้ ' + logical_id + ' ได้'});
				return next();
			}

			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 0) {
				console.error('Error D00X: Locker not available for reservation');
				res.send(401, { code: 'R001', message: 'สถานะในการจองไม่ถูกต้อง' });
				return next();
			} else {
				pgc.query('insert into reservation(locker_id, personal_id) values ($1, $2)',
						[locker_id, user_id], function(err, result) {
							if (err) {
								console.error('Error D00X: Cannot insert locker information to database');
								res.send(401, {code: 'L00X', message:'ไม่สามารถเพิ่มข้อมูลการจองได้ ' + logical_id + ' ได้'});
								return next();
							} else {
								// TODO: add reservation_id as response
								res.send(200/*, {reservation_id: }*/);
								io.sockets.emit('reserve', locker_id);

								var canmsg = { id: 0x280 + locker_id, ext: false, data: new Buffer([]) };
								can_ch.send(canmsg);

								console.log('Info: #' + locker_id + ' reserved by user u#' + req.user.id + ',' + req.user.username);
								return next();
							}
				});
			}
		});
	})

	server.post('lockers/:logical_id/release', function(req, res) {
		var logical_id = req.params['logical_id'];

		pgc.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			if (err) {
				console.error('Error D00X: Cannot get locker data from database');
				res.send(401, {code: 'L00X', message:'ไม่สามารถเรียกข้อมูลล็อกเกอร์ได้ ' + logical_id + ' ได้'});
				return next();
			}

			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				console.error('Error D00X: Invlid locker state change');
				res.send(401, { code: 'L00X', message: 'สถานะในการเลิกใช้งานไม่ถูกต้อง' });
				return next();
			} else {
				// conn.query("SELECT count(*) as count FROM reservation WHERE id IN (select max(id) from reservation group by locker_id) and personal_id=? group by personal_id", [personal_id], function(err, rows, result) {
				// TODO: using dynamic id from RFID card
				pgc.query("SELECT id FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, rows, result) {
					if (err) {
						console.error('Error D00X: No such reservation found');
						res.send(401, { code: 'L00X', message: 'ไม่พบการจองที่ต้องการ' });
						return next();
					}

					pgc.query("UPDATE locker SET state = 4 WHERE id = $1", [locker_id], function(err, result) {
						if (err) {
							console.error('Error D00X: Cannot update locker state');
							res.send(401, { code: 'L00X', message: 'ไม่สามารถเปลี่ยนสถานะล็อกเกอร์ได้' });
							return next();
						}
						res.send(200);
						io.sockets.emit('released', locker_id);
						
						var canmsg = { id: 0x480 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);

						console.log('Info: #' + locker_id + ' released by user u#' + req.user.id + ',' + req.user.username);
						return next();
					});
				});
			}
		});
	});


	// pgsql LISTEN/NOTIFY
	pgc.on('notification', function(msg) {
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

	pgc.query('LISTEN locker_is_alive_update');
	pgc.query('LISTEN locker_state_update');

});

