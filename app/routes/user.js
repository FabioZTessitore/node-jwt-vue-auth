const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const middleware = require('../middleware');

const User = require('../models/user');

const router = express.Router();

const TIMEUNIT = 3600;                  // 1h
const expiresIn = TIMEUNIT;             // 1h
const refreshExpiresIn = TIMEUNIT * 5;  // 5h

router.post('/signup', (req, res) => {
    const email = req.body.email;
    const password  = req.body.password;

    User.findOne({ 'email': email }, (err, user) => {
        if (err) {
            res.status(500);
            res.json({ auth: false, msg: 'Cannot register the user.' });
            return;
        }

        if (user) {
            res.status(401);
            res.json({ auth: false, msg: 'Email already in db.' });
            return;
        }

        var newUser = new User();
        newUser.email = email;
        newUser.password = newUser.generateHash(password);
  
        newUser.save( (err, user) => {
            if (err) {
                res.status(500);
                res.json({ auth: false, msg: 'Error registering the user.' });
                return;
            }
  
            const token = jwt.sign({ id: user._id }, config.secret, { expiresIn: expiresIn });
            const refreshToken = jwt.sign({ id: user._id }, config.secret, { expiresIn: refreshExpiresIn });
            res.status(200).json({ auth: true, token: token, refreshToken: refreshToken, expiresIn: expiresIn });
        });
    });
});

router.post('/login', (req, res) => {
    const email = req.body.email;
    const password  = req.body.password;
    
    User.findOne({ 'email': email }, (err, user) => {
        if (err) {
            res.status(500);
            res.json({ auth: false, msg: 'Server Error' });
            return;
        }

        if (!user) {
            res.status(404);
            res.json({ auth: false, msg: 'Cannot find user' });
            return;
        }

        let passwordIsValid = user.validPassword(password);
        if (!passwordIsValid) {
            res.status(401);
            res.json({ auth: false, msg: 'Invalid password' });
            return;
        }

        const token = jwt.sign({ id: user._id }, config.secret, { expiresIn: expiresIn });
        const refreshToken = jwt.sign({ id: user._id }, config.secret, { expiresIn: refreshExpiresIn });
        res.status(200).json({ auth: true, token: token, refreshToken: refreshToken, expiresIn: expiresIn });
    });
});

router.post('/refresh-token', (req, res) => {
    const refreshToken = req.body.refreshToken;

    if (!refreshToken) {
        res.status(401);
        return res.json({
            auth: false,
            msg: 'Refresh token is not supplied'
        });
    }
    
    jwt.verify(refreshToken, config.secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                auth: false,
                msg: 'Token is not valid'
            });
        } else {
            const userId = decoded.id;
            const token = jwt.sign({ id: userId }, config.secret, { expiresIn: expiresIn });
            res.status(200).json({ auth: true, token: token });
        }
    });
});

router.get('/userdata', middleware.checkToken, (req, res) => {
    const userId = req.decoded.id;

    User.findById(userId, (err, user) => {
        if (err) {
            res.status(500);
            res.json({ auth: false, msg: 'Server Error' });
            return;
        }

        if (!user) {
            res.status(404);
            res.json({ auth: false, msg: 'Cannot find user' });
            return;
        }

        res.status(200).json({ auth: true, user: { id: user._id, email: user.email } });
    });
});

let counter = 0;
router.get('/secure-data', middleware.checkToken, (req, res) => {
    counter++;
    res.status(200).json({ counter });
});


module.exports = router;