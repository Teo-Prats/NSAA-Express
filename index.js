const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy
const app = express()
const port = 3000
const { promisify } = require('util')
const fs = require('fs')
const { hash, verify } =  require('scrypt-mcf')
const sqlite3 = require('sqlite3').verbose()

const dbFile = './users.db' 
const dbExists = fs.existsSync(dbFile)
const db = new sqlite3.Database(dbFile)



// SQLite Database Initialization
if (!dbExists) {
  db.serialize(async() => {
    db.run("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT)")
    
    const username = 'walrus';
    const password = 'walrus'; 
    const start = performance.now();
    const mcfString = await hash(password, { derivedKeyLength: 64, scryptParams: { logN: 12, r: 8, p: 1 } });  
  // const mcfString = await hash(password, { derivedKeyLength: 64, scryptParams: { logN: 18, r: 8, p: 7 } });
    const end = performance.now();
    console.log('hash:', mcfString);
    console.log('time:', end - start, 'milliseconds');
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, mcfString], (err) => {
      if (err) {
        console.error('Error al insertar usuario en la base de datos:', err);
      } 
    });
  });
}


app.use(logger('dev'))
app.use(cookieParser())

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  
    passwordField: 'password',  
    session: false 
  },
  function (username, password, done) {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
      if (err) { return done(err); }
      if (!row) { return done(null, false); }
      
      if (verify(password, row.password)) {
        return done(null, { username: row.username });
      } else {
        return done(null, false);
      }
    });
  }
));

passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub && jwtPayload.sub === 'walrus') {
      const user = { 
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      }
      return done(null, user)
    }
    return done(null, false)
  }
))

app.use(express.urlencoded({ extended: true })) 
app.use(passport.initialize())  

app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) 
  }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.get('/logout', (req, res) => {
  res.clearCookie('jwt'); 
  res.redirect('/login'); 
});

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), 
  (req, res) => { 
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, 
      role: 'user' 
    }
    const token = jwt.sign(jwtClaims, jwtSecret)
    res.cookie('jwt', token, { httpOnly: true, secure: true })
    res.redirect('/')

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
