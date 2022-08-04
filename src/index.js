import cors from 'cors';
import express from 'express';
import Session from 'express-session';
import { generateNonce, SiweMessage } from 'siwe';
/*
import connectRedis from 'connect-redis';
import Redis from 'redis';
let RedisStore = connectRedis(Session);

const REDISHOST = process.env.REDISHOST || '10.13.153.171';
const REDISPORT = process.env.REDISPORT || 6379;

let redisClient = Redis.createClient({socket: {
    host: REDISHOST,
    port: REDISPORT
}});

redisClient.connect().catch(console.error)
*/

const app = express();
app.use(express.json());
app.use(cors({
  origin: function(origin, callback){
    return callback(null, true);
  },
  optionsSuccessStatus: 200,
  credentials: true
}));

/*app.use(
    Session({
      store: new RedisStore({ client: redisClient }),
      saveUninitialized: false,
      secret: "keyboard cat try me",
      resave: false,
      cookie: { secure: true, SameSite: 'none' }
    })
  )
*/

app.use(Session({
    name: 'siwe-quickstart',
    secret: "siwe-quickstart-secret",
    resave: true,
    saveUninitialized: true,
    cookie: { secure: true, SameSite: 'none' }
}));

app.get('/nonce', async function (req, res) {
    req.session.nonce = generateNonce();
    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(req.session.nonce);
});

app.post('/verify', async function (req, res) {
    try {
        if (!req.body.message) {
            res.status(422).json({ message: 'Expected prepareMessage object as body.' });
            return;
        }

        let message = new SiweMessage(req.body.message);
        const fields = await message.validate(req.body.signature);
        if (fields.nonce !== req.session.nonce) {
            console.log("invalid nonce.");
            //console.debug("Request Session: " + req.session);
            console.debug("Request Signature: " + req.body.signature);
            console.debug("Request Session Nonce: " + req.session.nonce);
            console.debug("Fields Nonce: " + fields.nonce)
            console.debug("Request Body Message: " + req.body.message);
            res.status(422).json({
                message: `Invalid nonce.`,
            });
            return;
        }
        req.session.siwe = fields;
        req.session.cookie.expires = new Date(fields.expirationTime);
        req.session.save(() => res.status(200).end());
    } catch (e) {
        req.session.siwe = null;
        req.session.nonce = null;
        console.error(e);
        switch (e) {
            case ErrorTypes.EXPIRED_MESSAGE: {
                req.session.save(() => res.status(440).json({ message: e.message }));
                break;
            }
            case ErrorTypes.INVALID_SIGNATURE: {
                req.session.save(() => res.status(422).json({ message: e.message }));
                break;
            }
            default: {
                req.session.save(() => res.status(500).json({ message: e.message }));
                break;
            }
        }
    }
});

app.get('/personal_information', function (req, res) {
    if (!req.session.siwe) {
        res.status(401).json({ message: 'You have to first sign_in' });
        return;
    }
    console.log("User is authenticated!");
    res.setHeader('Content-Type', 'text/plain');
    res.send(`You are authenticated and your address is: ${req.session.siwe.address}`)
});

app.listen(3000);
