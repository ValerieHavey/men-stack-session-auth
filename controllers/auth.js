const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');

//localhost:3000/auth/sign-up
router.get('/sign-up', (req, res) => {
    res.render('auth/sign-up.ejs');
});

router.post('/sign-up', async (req, res) => {
    //Let's check for unique username
    const userInDatabase = await User.findOne({ username: req.body.username });

    if (userInDatabase) {
        return res.send('Username already taken.');
    }

    //Let's check `password` and `confirmPassword` are the same
    if (req.body.password !== req.body.confirmPassword) {
        return res.send('Password and Confirm Password must match!');
    }

    //Let's securely store our password
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    req.body.password = hashedPassword;

    const user = await User.create(req.body);

    res.send(`Thanks for signing up, ${user.username}`);
})

router.get('/sign-in', (req, res) => {
    res.render('auth/sign-in.ejs');
})

router.post('/sign-in', async (req, res) => {
    //Let's check if the username exists in the DB
    const userInDatabase = await User.findOne({ username: req.body.username});

    if (!userInDatabase) {
        return res.send('Login failed. Please try again');
    }

    const validPassword = bcrypt.compareSync(req.body.password, userInDatabase.password);

    if (!validPassword) {
        return res.send('Login failed. Please try again');
    }

    req.session.user = {
        username: userInDatabase.username,
        _id: userInDatabase._id,
    };

    res.redirect('/');
});

router.get('/sign-out', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

module.exports = router;
