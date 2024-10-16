const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const app = express();

const mongoose = require('mongoose');
const methodOverride = require('method-override');
const morgan = require('morgan');
const session = require('express-session');

const authController = require('./controllers/auth.js');

const port = process.env.PORT ? process.env.PORT : '3000';

mongoose.connect(process.env.MONGODB_URI);

mongoose.connection.on('connected', () => console.log(`Connected to Mongo DB ${mongoose.connection.name}`));

//Let's set up our middleware
app.use(express.urlencoded({ extended: false}));
app.use(methodOverride('_method'));
app.use(morgan('dev'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}))

app.get('/', (req, res) => {
    res.render('index.ejs', {user: req.session.user});
});

app.use('/auth', authController);

app.get('/vip-lounge', (req, res) => {
    if (req.session.user) {
        res.send(`Welcome to the party, ${req.session.user.username}`);
    } else {
    res.send (`Sorry, no guests allowed.`);
}
})

app.listen(port, () => console.log(`Express is running on port ${port}`));

