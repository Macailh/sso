require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const swaggerUi = require('swagger-ui-express')
const swaggerFile = require('./swagger-output.json')

const app = express();
app.use(express.json());

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerFile))

const users = []; // Esto debería ser reemplazado por una base de datos real

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
let refreshTokens = []; // En un caso real, esto debería ser almacenado de manera más segura

app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { username: req.body.username, password: hashedPassword };
        users.push(user);
        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).send('Error registering the user');
    }
});

app.post('/login', async (req, res) => {
    const user = users.find(u => u.username === req.body.username);
    if (user == null) {
        return res.status(400).send('Cannot find user');
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign({ username: user.username }, accessTokenSecret, { expiresIn: '20m' });
            const refreshToken = jwt.sign({ username: user.username }, refreshTokenSecret);
            refreshTokens.push(refreshToken);
            res.json({ accessToken, refreshToken });
        } else {
            res.send('Not Allowed');
        }
    } catch {
        res.status(500).send();
    }
});

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, refreshTokenSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = jwt.sign({ username: user.username }, accessTokenSecret, { expiresIn: '20m' });
        res.json({ accessToken });
    });
});

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
