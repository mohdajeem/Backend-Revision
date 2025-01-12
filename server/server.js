import express from "express";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// part 2
import cookieParser from 'cookie-parser';

const app = express();
const PORT = 3000;

// middleware to parse json
app.use(express.json());
// part 2 middleware
app.use(cookieParser());





// 2. Refresh Tokens for Extended Authentication
/*
    JWT access tokens usually have a short lifespan for security (e.g., 1 hour).
    Once expired, the user would need to log in again.
    A refresh token allows users to request a new access token without re-logging in.

    On login we get -> accessToken(Short time), refreshToken(Long time for refreshing access Token) -> HTTP-only cookie(stored in).
    first we have to require cookie-parser.
*/

const users = [
    {
        id:1,
        username: 'john',
        password: await bcrypt.hash("password123",10),
    },
    {
        id:2,
        username: 'ajeem',
        password: await bcrypt.hash("pass123",10),
    },
];

// secret key for signing tokens (access Token)
const SECRET_KEY = 'Ajeem';

// part 2 - secret key for refresh token
const REFRESH_SECRET_KEY = 'MohdAjeem';

// Store the refresh tokens (in memory for simplicity)
const refreshTokens = [];

// Generate Tokens 
const generateAccessToken = (user)=> jwt.sign(user, SECRET_KEY, {expiresIn: '1h'});
const generateRefreshToken = (user) => jwt.sign(user, REFRESH_SECRET_KEY);

// Login Route

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body;
    const user = users.find((u)=>u.username === username);
    
    if(!user || !(await bcrypt.compare(password, user.password))){
        res.status(401).json({error: 'Invalid Credentials'});
    }
    const accessToken = generateAccessToken({id: user.id, username:user.username});
    const refreshToken = generateRefreshToken({id: user.id, username: user.username});
    refreshTokens.push(refreshToken);

    res.cookie('refreshToken', refreshToken, {httpOnly: true, secure:true});
    res.status(200).json({message:"Login Successful", accessToken});
})

// Refresh Token Route
app.post('/api/token', (req, res) => {
    const {refreshToken} = req.body;

    if(!refreshToken || !refreshTokens.includes(refreshToken)){
        return res.status(403).json({error:'Refresh Token not found or invalid'});
    }

    jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
        if(err){
            return res.status(403).json({error: 'Invalid refresh token'});
        }

        const accessToken = generateAccessToken({id: user.id, username: user.username});
        res.status(200).json({message:'access token regenerated', accessToken});
    });
});

// Logout route
app.post('api/logout', (req, res) => {
    const {refreshToken} = req.cookies;
    refreshTokens.splice(refreshTokens.indexOf(refreshToken), 1);
    res.clearCookie('refreshToken');
    res.status(200).json({message: 'Logged out successfully'});

})

// middleware to validate JWT
const authenticateToken = (req, res, next) =>{
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if(!token){
        return res.status(403).json({message:'Invalid token', error:"Invalid token"});
    }

    jwt.verify(token,SECRET_KEY, (err, user) => {
        if(err){
            return res.status(403).json({error:'Invalid token'});
        }
        req.user = user;
        next();
    })
};

// protected Routes
app.get('/api/protected', authenticateToken, (req, res)=>{
    res.status(200).json({message:"Welcome to the Protected route"});
});



//------------------------------------------------------

/* 
        PART - 1

// Generate JWT on login

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body;

    // find the user
    const user = users.find((u) => u.username === username);
    if(!user){
        return res.status(404).json({message: 'User not found',error : 'User not found'});
    }

    // Validate the password 
    const isPasswordValid = await bcrypt.compare(password,user.password);
    if(!isPasswordValid) {
        return res.status(401).json({message: 'Invalid Credentials', error:'Invalid username or password'});
    }

    // generate JWT token -- jwt.sign(payload, secret, options)
    const token = jwt.sign({id: user.id, username:user.username}, SECRET_KEY, {
        expiresIn:'1h'
    })

    return res.status(200).json({message: 'Login Successfull', token});
});

// middleware to validate JWT
const authenitcateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if(!token){
        return res.status(401).json({error: 'Token is missing'});
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if(err){
            return res.status(403).json({error: 'Invalid Token'});
        }
        req.user = user;
        next();
    });
};

// protected route
app.get('/api/protected', authenitcateToken, (req, res) => {
    res.status(200).json({
        message: `Hello ${req.user.username}, welcome to the protected route!`,
    })
})


*/

// Start the server 
app.listen(PORT, ()=> {
    console.log(`Server is running on http://localhost:${PORT}`);
})