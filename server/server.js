import express from "express";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 3000;

// middleware to parse json
app.use(express.json());

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

// secret key for signing tokens
const SECRET_KEY = 'Ajeem';

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

// Start the server 
app.listen(PORT, ()=> {
    console.log(`Server is running on http://localhost:${PORT}`);
})