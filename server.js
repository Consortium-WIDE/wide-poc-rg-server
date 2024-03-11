require('dotenv').config();
const cors = require('cors');
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { redisClient } = require('./clients/redisClient'); // Your Redis client

const app = express();
app.set('trust proxy', 1); // Trust the first proxy
app.use(express.json());
app.use(cookieParser());

// CORS configuration for the WIDE domain
const wideCorsOptions = {
    origin: process.env.WIDE_DOMAIN,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
};

// CORS configuration for the WEB domain
const webCorsOptions = {
    origin: process.env.WEB_DOMAIN,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
};

let cookieConfig = {
    httpOnly: true,
    secure: process.env.COOKIE_USE_SECURE === 'true',
    sameSite: process.env.COOKIE_SAME_SITE || 'lax',
    maxAge: parseInt(process.env.COOKIE_EXPIRY_MILLISECONDS, 10) || 3600000
}

if (process.env.COOKIE_DOMAIN != 'LOCAL') {
    cookieConfig.domain = process.env.COOKIE_DOMAIN;
}


console.log('cookieConfig', cookieConfig);

app.use(session({
    name: 'rgdm.sid',
    secret: process.env.SESSION_SECRET, // Secret used to sign the session ID cookie
    store: new RedisStore({ client: redisClient, prefix: 'rgdm-session-' }),
    resave: false,
    saveUninitialized: false,
    cookie: cookieConfig
}));

console.log('starting server for CORS origin: ', process.env.WEB_DOMAIN);

const wideDataService = require('./routes/wideDataService');
app.use('/wide', cors(wideCorsOptions), wideDataService);

const rgdmService = require('./routes/rgdmService');
app.use('/rgdm', cors(webCorsOptions), rgdmService);

app.get('/', (req, res) => {
    res.send('Hello World!');
  });

// Define Port
const PORT = process.env.PORT || 3500;

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});