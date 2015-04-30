var restify = require('restify');
var pg = require('pg');
var pg_constr = "postgres://postgres:password@192.168.100.252/locker_api";
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
server.use(rjwt({ secret: secret }).unless( {path: ['/login', '/test', '/qx']} ));

// CAN
var can_ch = can.createRawChannel('can0', true);
can_ch.start();

server.listen(8080, function () {
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



	can_ch.addListener('onMessage', function(msg) {
		var can_cmd = msg.id & 0x700;
		var locker_id = msg.id & 0x0FF;
		if (can_cmd == 0x100) {
			// locker registration request
			// check if msg.data[0] (LID) is in database
			client.query('select id, logical_id, state from locker where id = $1', [locker_id], function(err, result) {
				var locker = result.rows[0];

				// if there's no data, create new row for it
				if (result.rows[0] === undefined) {
					client.query('insert into locker(id, state) values ($1, $2)', [locker_id, 0], function(err, result) {
						if (!err) {
							var regd = { id: 0x180 + locker_id, ext: false, data: new Buffer([]) };
							can_ch.send(regd);
						}
					});
				} else {
					// locker data exists
					// now determine if it's configured or not
					console.log(result.rows[0]);
					if (locker_id == locker.id) {
						if (result.rows[0].logical_id == null) {
							var regd = { id: 0x180 + locker_id, ext: false, data: new Buffer([])};
							can_ch.send(regd);
						} else {
							var confd = { id: 0x200 + locker_id, ext: false, data: new Buffer([])};
							can_ch.send(confd);
						}
						
					}
				}
			});
		} else if (msg.id == 0x300) {
			var uid = msg.data.toString('hex');

			var query = 	"select id from locker where id = ( \
								select locker_id from reservation where id = ( \
									select max(id) from reservation where personal_id = ( \
										select id from locker_user where encode(rfid_uid, 'hex') = $1 \
									) \
								group by locker_id \
								) \
							) \
							and (state = 1 or state = 3)";


			client.query(query, [uid], function(err, result_i) {
				// console.log(result_i);
				if (undefined === result_i.rows[0]) {
					return;
				}
				var locker_id = result_i.rows[0].id;
				client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, result_ii) {
					console.log(result_ii.rows);

					if (!result_ii.rows[0].is_activated) {
						client.query("UPDATE reservation SET is_activated = 't' WHERE id = $1", [result_ii.rows[0].id]);
					}

					client.query("UPDATE locker SET state = 2 WHERE id=$1", [locker_id], function(err, result_iii) {
						// TODO: catch err
						// if (err) throw err;
						// console.log('locker ' + locker_id + ' opened');

						var canmsg = { id: 0x380 + locker_id, ext: false, data: new Buffer([]) };
						can_ch.send(canmsg);
					});

				});
			})

		} else if (can_cmd == 0x400) {
			client.query('select id, logical_id, state from locker where state=2 and id=$1', [locker_id], function(err, result) {
				var locker = result.rows[0];

				client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id = $1)", [locker_id], function(err, result_i) {
					if (err) throw err;

					if (result_i.rows.length == 0) {
						return;
					}

					if (2 != locker.state) {
						// throw "Invalid closing state";
						return;
					} else {
						client.query("UPDATE locker SET state = 3 WHERE id=$1", [locker_id], function(err, result) {
							if (err) throw err;

							console.log('locker ' + locker_id + ' closed');
							// var canmsg = { id: 0x400 + locker_id, ext: false, data: new Buffer([]) };
							// can_ch.send(canmsg);
						});
					}
				});
			});
		}
	})

	server.post('/login', function(req, res, next) {
		var username = req.params.username || '';
		var password = req.params.password || '';
		if (username == '' || password == '') {
			res.send(401, {code: 'emptyuserpassword', message: 'ชื่อผู้ใช้หรือรหัสผ่านเป็นค่าว่าง'});
		}


		client.query('select id from locker_user where username = $1 and password = $2', [username, sha1(password)], function(err, result) {
			if (err) {
				throw err;
			}

			if (result.rows.length == 0) {
				res.send(401, {code: 'invaliduserpassword', message:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'});
			}

			var profile = {
				id: result.rows[0].id,
				user: username
			};

			var token = jwt.sign(profile, secret);
			res.json({ token: token });
		})
	});


	server.get('/test', function(req, res, next) {
		client.query('select id, logical_id, state from locker where id = 8', function(err, result) {
			res.send(result.rows[0]);
		});
	});


	server.get('/qx', function(req, res, next) {
		var uid = '8302372e9800';

		var query = 	"select id from locker where id = ( \
							select locker_id from reservation where id = ( \
								select max(id) from reservation where personal_id = ( \
									select id from locker_user where encode(rfid_uid, 'hex') = $1 \
								) \
							group by locker_id \
							) \
						) \
						and (state = 1 or state = 3)";

		client.query(query, [uid], function(err, result_i) {
			console.log(result_i);
			var locker_id = result_i.rows[0].id;
			client.query("SELECT id, is_activated FROM reservation WHERE id = (SELECT max(id) FROM reservation WHERE locker_id=$1)", [locker_id], function(err, result_ii) {
				console.log(result_ii.rows);

				if (!result_ii.rows[0].is_activated) {
					client.query("UPDATE reservation SET is_activated = 't' WHERE id = $1", [result_ii.rows[0].id]);
				}

				client.query("UPDATE locker SET state = 2 WHERE id=$1", [locker_id], function(err, result_iii) {
					// TODO: catch err
					console.log('yyy');
					// if (err) throw err;
					// console.log('locker ' + locker_id + ' opened');
					res.send(200);

					var canmsg = { id: 0xA, ext: false, data: new Buffer([locker_id]) };
					can_ch.send(canmsg);
				});

			});
		})

	});

	server.get('/user/is_reserved', function(req, res, next) {
		var user_id = req.user.id;

		client.query('select l.logical_id from reservation r, locker l where r.id in ( \
			select max(id) from reservation group by locker_id \
			) and l.state > 0 and personal_id = $1 and l.id = r.locker_id', [user_id], function(err, result) {
			res.send({ is_reserved: result.rows.length > 0 ? result.rows[0].logical_id : 'false'});
		})
	});

	server.get('/history', function(req, res, next) {
		var user_id = req.user.id;
		var page = req.params['page'] || 0;

		client.query("select a.id, a.created, a.state, a.reservation_id, l.logical_id from activity a, reservation r, locker l \
			where a.reservation_id in (select r.id from reservation r where r.personal_id = $1 order by id desc limit 5 offset $2) \
				and a.reservation_id = r.id and r.locker_id = l.id \
			order by a.id asc", [user_id, 5*page], function(err, result) {
			if (err) {
				return;
			}
			res.send(result.rows);
		})
	});

	server.get('/echo/:name', function (req, res, next) {
		res.send(req.params);
		return next();
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

	server.post('/lockers/:logical_id/reserve', function(req, res) {
		var user_id = req.user.id;
		var logical_id = req.params['logical_id'];
		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 0) {
				res.send(401, { code: 'R001', message: 'สถานะในการจองไม่ถูกต้อง' });
			} else {
				// TODOL validating data first
				client.query('insert into reservation(locker_id, personal_id) values ($1, $2)',
						[locker_id, user_id], function(err, result) {
							if (err) {
								console.log(err);
							} else {
								res.send(200);
								io.sockets.emit('reserve', locker_id);
								var canmsg = { id: 0x280 + locker_id, ext: false, data: new Buffer([]) };
								can_ch.send(canmsg);
							}
				});
			}
		});
		// return next();
	})

	// This method is not to be used by normal user
	// user'll typically open and close locker by RFID authorization
	// which sen CAN message the controller
	server.post('lockers/:logical_id/open', function(req, res) {
		var logical_id = req.params['logical_id'];

		client.query('select id, state from locker where is_alive=true and logical_id = $1', [logical_id], function(err, result) {
			var locker_id = result.rows[0].id;
			var state = result.rows[0].state;

			if (state != 1 && state != 3) {
				res.send(401, { code: 'R002', message: 'สถานะในการเปิดไม่ถูกต้อง' });
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
				res.send(401, { code: 'R004', message: 'สถานะในการเลิกใช้งานไม่ถูกต้อง' });
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

