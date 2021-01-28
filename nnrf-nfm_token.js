require('sslkeylog').hookAll();
const jsonServer = require('json-server');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const spdy = require('spdy');
const fs = require('fs');
const path = require('path');
const pause = require('connect-pause');

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());

var expires_in;

function verifyToken(token) {
  const PUB_KEY = fs.readFileSync(__dirname + '/server.crt', 'utf8');
  return jwt.verify(token, PUB_KEY, { algorithms: ['RS256'] }, (err, decode) => decode !== undefined ?  decode : err);
  /*
  jwt.verify(token, PUB_KEY, { algorithms: ['RS256'] }, (err, decoded) => {
    if(typeof decoded.exp !== 'undefined' && decoded.exp < now) {
      return 'Token Expire';
    } 
    if(err) {
      if (err.name === 'TokenExpiredError') {
          console.log('Whoops, your token has expired!');
      }
      
      if (err.name === 'JsonWebTokenError') {
          console.log('That JWT is malformed!');
      }
    } else if (err === null) {
      console.log('Your JWT was successfully validated!');
      console.log(decoded);
    }
  });
  //*/
}

function createToken(grant_type,nfInstanceId, scope) {
  const PRIV_KEY = fs.readFileSync(__dirname + '/server.key', 'utf8');

  const payloadObj = {
    iss: 'bbdb6ce7-5fb6-41de-a2a1-ad904e934184', // NRF Instance ID
    sub: nfInstanceId, // Consumer Instance Id
    aud: '504e9f59-43ce-4deb-ac60-51a91df7fca9', // Producer Instance ID
    scope: scope,
    exp: Math.floor(new Date().getTime() / 1000)+3600
  };

  const signedJWT = jwt.sign(payloadObj, PRIV_KEY, { algorithm: 'RS256'});
  expires_in = payloadObj.exp
  return signedJWT;
}

// To handle POST, PUT and PATCH you need to use a body-parser
// You can use the one used by JSON Server
server.use(jsonServer.bodyParser);

server.post('/oauth2/token', (req, res) => {
  const {grant_type, nfInstanceId, scope} = req.body
  const access_token = createToken({grant_type, nfInstanceId,scope})
  //const access_token = createToken({grant_type, nfInstanceId,scope})
  const token_type = "Bearer"
  res.status(200).json({access_token, token_type, expires_in, scope})
});

server.use(/^(?!\/oauth2).*$/,(req, res, next) => {
  //if (req.method === 'POST') {
  //  req.body.createdAt = Date.now()
  //}
  //*
  var status
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    status = 401
    const message = 'Bad authorization header'
    res.status(status).json({status, message})
    return
  }
  const token = req.headers.authorization.split(' ')[1]
  const PUB_KEY = fs.readFileSync(__dirname + '/server.crt', 'utf8');
    jwt.verify(token, PUB_KEY, { algorithms: ['RS256'] }, (err, decoded) => {
      if(err) {
        if (err.name === 'TokenExpiredError') {
          status = 401
          const message = 'TokenExpiredError'
          console.log('Whoops, your token has expired!');
          res.status(status).json({status, message})
      }
      
      if (err.name === 'JsonWebTokenError') {
          status = 401
          const message = 'That JWT is malformed!'
          console.log(message);
          res.status(status).json({status, message})
      }
      } else if (err === null) {
        console.log('Your JWT was successfully validated!');
        next()
      }
    });
  //*/
  // Continue to JSON Server router
})

server.use(pause(2000));
server.use(router);

// If using custom routes
var routes = JSON.parse(fs.readFileSync('routes.json'));
server.use(jsonServer.rewriter(routes));

const options = {
    ca: fs.readFileSync('ca.crt'),
    cert: fs.readFileSync('server.crt'),
    key: fs.readFileSync('server.key'),
    rejectUnauthorized: true,
    requestCert: true,
};

spdy
  .createServer(options,server)
  .listen(3000, () => {
     console.log(
  'Go to https://localhost:3000/'
     );
  })
  .on('keylog', line => fs.appendFileSync('keylogmutualtls', line));


//spdy.on('keylog', line => fs.appendFileSync('keylogmutualtls', line))
/*
spdy.on('keylog', line => 
  fs.appendFileSync('keylogmutualtls', line));

/*
const server = https.createServer(options, (req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World');
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
})
*/;
