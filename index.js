/* eslint-disable no-unused-vars */
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');
// eslint-disable-next-line import/no-extraneous-dependencies
const { restart } = require('nodemon');
const connection = require('./database');

const { SERVER_PORT, CLIENT_URL, JWT_AUTH_SECRET } = process.env;

const app = express();

app.use(
  cors({
    origin: CLIENT_URL,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Your code here!

const authenticateWithJsonWebToken = (req, res, next) => {
  if (req.headers.authorization !== undefined) {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, JWT_AUTH_SECRET, (err) => {
      if (err) {
        res
          .status(401)
          .json({ errorMessage: "you're not allowed to access these data" });
      } else {
        console.log('ok');
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ errorMessage: 'you are not allowed to access these data' });
  }
};

app.get('/users', authenticateWithJsonWebToken, (req, res) => {
  connection.query('SELECT * FROM user', (error, results) => {
    if (error) {
      throw error;
    } else {
      res.status(200).json(
        results.map((user) => {
          return { ...user, password: 'hidden' };
        })
      );
    }
  });
});

app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).send('Please specify both email and password');
  } else {
    const hash = bcrypt.hashSync(password, 10);
    connection.query(
      'INSERT INTO user (email, password) VALUES (?, ?)',
      [email, hash],
      (error, results) => {
        if (error) {
          res.status(500).send(error);
        } else {
          res.status(201).send({
            id: results.insertId,
            ...req.body,
            password: 'hidden',
          });
        }
      }
    );
  }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).send('Please specify both email and password');
  } else {
    connection.query(
      'SELECT * FROM user WHERE email = ?',
      [email],
      (error, results) => {
        if (error) {
          res.status(500).send(error);
        } else if (results.length === 0) {
          res.status(403).send('Invalid email');
        } else {
          connection.query(
            'SELECT password FROM user WHERE email = ?',
            email,
            (err, result) => {
              if (err) {
                res.status(500).send(error);
              } else {
                const passwordDB = results[0].password;
                bcrypt.compare(password, passwordDB, (berror, bresult) => {
                  if (berror) {
                    res.status(500).send(berror);
                  } else if (bresult) {
                    connection.query(
                      'SELECT * FROM user WHERE email = ?',
                      email,
                      (errtuple, resulttuple) => {
                        if (errtuple) {
                          res.status(500).send(error);
                        } else {
                          const token = jwt.sign(
                            { id: resulttuple[0].id },
                            JWT_AUTH_SECRET,
                            {
                              expiresIn: 300,
                            }
                          );
                          // eslint-disable-next-line no-param-reassign
                          resulttuple[0].password = 'hidden';
                          res.status(200).send({
                            ...resulttuple[0],
                            token,
                          });
                        }
                      }
                    );
                  } else {
                    res.status(403).send('Invalid password');
                  }
                });
              }
            }
          );
        }
      }
    );
  }
});

// Don't write anything below this line!
app.listen(SERVER_PORT, () => {
  console.log(`Server is running on port ${SERVER_PORT}.`);
});
