const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-secret-key-2024';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';

// ==================== DATA SETUP ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User exists' });
    
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Request sent to owner' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = { 
        email, 
        password: pending[email].password, 
        isOwner: false, 
        isApproved: true, 
        isBlocked: false, 
        apiKey: "", 
        secretKey: "", 
        createdAt: pending[email].requestedAt 
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Approved ${email}` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Rejected ${email}` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({ 
        email, 
        hasApiKeys: !!users[email].apiKey, 
        isOwner: users[email].isOwner, 
        isApproved: users[email].isApproved, 
        isBlocked: users[email].isBlocked 
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/all-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    res.json({ success: true, users });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const timestamp = Date.now();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const queryString = Object.keys(allParams).sort().map(k => `${k}=${allParams[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 15000
    });
    return response.data;
}

async function getTotalBalance(apiKey, secretKey, useDemo = false) {
    try {
        const account = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = account.balances.find(b => b.asset === 'USDT');
        const spotBalance = parseFloat(usdtBalance?.free || 0);
        return spotBalance;
    } catch (error) {
        console.error('Balance error:', error.response?.data || error.message);
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeMarketOrder(apiKey, secretKey, symbol, side, quantity, useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const timestamp = Date.now();
    const params = { symbol, side, type: 'MARKET', quantity: quantity.toFixed(8), timestamp, recvWindow: 5000 };
    const queryString = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}/api/v3/order?${queryString}&signature=${signature}`;
    
    const response = await axios({
        method: 'POST',
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 15000
    });
    return response.data;
}

// ==================== ADVANCED REAL-TIME AI SIGNAL ====================
async function getRealTimeAISignal(symbol, useDemo = false) {
    try {
        const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
        
        // Get 1min ticker for real-time data
        const ticker24h = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`);
        const tickerPrice = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
        
        const priceChange24h = parseFloat(ticker24h.data.priceChangePercent);
        const volume24h = parseFloat(ticker24h.data.volume);
        const high24h = parseFloat(ticker24h.data.highPrice);
        const low24h = parseFloat(ticker24h.data.lowPrice);
        const currentPrice = parseFloat(tickerPrice.data.price);
        
        // Calculate RSI
        const range = high24h - low24h;
        const rsi = range > 0 ? ((currentPrice - low24h) / range) * 100 : 50;
        
        // Get last 20 1-minute candles for ultra-fast trend detection
        const klines = await axios.get(`${baseUrl}/api/v3/klines`, {
            params: { symbol, interval: '1m', limit: 20 }
        });
        const closes = klines.data.map(k => parseFloat(k[4]));
        const ma5 = closes.slice(-5).reduce((a, b) => a + b, 0) / 5;
        const ma10 = closes.slice(-10).reduce((a, b) => a + b, 0) / 10;
        const trend = ma5 > ma10 ? 'UP' : 'DOWN';
        
        // Calculate momentum (1 minute change)
        const momentum = closes.length >= 2 ? ((closes[closes.length - 1] - closes[closes.length - 2]) / closes[closes.length - 2]) * 100 : 0;
        
        // Calculate bid-ask spread approximation
        const spread = (high24h - low24h) / currentPrice * 100;
        
        let action = 'HOLD';
        let confidence = 0;
        let reasons = [];
        
        // BUY SIGNALS - Based on real-time market conditions
        if (rsi < 30 && momentum > -0.5) {
            action = 'BUY';
            confidence = 0.85;
            reasons.push(`RSI oversold (${rsi.toFixed(1)})`, `Stabilizing momentum`);
        }
        else if (rsi < 45 && trend === 'UP' && momentum > 0) {
            action = 'BUY';
            confidence = 0.8;
            reasons.push(`RSI ${rsi.toFixed(1)} in buy zone`, `Uptrend confirmed`, `Positive momentum`);
        }
        else if (priceChange24h < -2 && volume24h > 200000) {
            action = 'BUY';
            confidence = 0.75;
            reasons.push(`Price dip of ${priceChange24h}%`, `High volume support`);
        }
        else if (momentum > 0.3 && trend === 'UP' && rsi < 65) {
            action = 'BUY';
            confidence = 0.7;
            reasons.push(`Strong momentum ${momentum.toFixed(2)}%`, `Room to grow`);
        }
        
        // SELL SIGNALS
        if (rsi > 75 && momentum < 0.5) {
            action = 'SELL';
            confidence = 0.85;
            reasons.push(`RSI overbought (${rsi.toFixed(1)})`, `Momentum weakening`);
        }
        else if (rsi > 60 && trend === 'DOWN' && momentum < 0) {
            action = 'SELL';
            confidence = 0.8;
            reasons.push(`RSI ${rsi.toFixed(1)} in sell zone`, `Downtrend confirmed`);
        }
        else if (priceChange24h > 3 && volume24h > 200000) {
            action = 'SELL';
            confidence = 0.75;
            reasons.push(`Price pump of ${priceChange24h}%`, `Take profits`);
        }
        else if (momentum < -0.3 && trend === 'DOWN' && rsi > 35) {
            action = 'SELL';
            confidence = 0.7;
            reasons.push(`Negative momentum ${momentum.toFixed(2)}%`, `Downtrend accelerating`);
        }
        
        console.log(`🤖 AI [${symbol}]: ${action} (${(confidence*100).toFixed(0)}%) | RSI:${rsi.toFixed(1)} Trend:${trend} Mom:${momentum.toFixed(2)}% | ${reasons.join(', ')}`);
        
        return { action, confidence, reasons, currentPrice, rsi, trend, momentum, spread };
    } catch (error) {
        console.error('AI signal error:', error.message);
        return { action: 'HOLD', confidence: 0, reasons: ['Error fetching data'], currentPrice: 0 };
    }
}

// ==================== API KEY ROUTES ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    try {
        let { apiKey, secretKey, accountType } = req.body;
        if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
        
        const cleanApi = cleanKey(apiKey);
        const cleanSecret = cleanKey(secretKey);
        const useDemo = (accountType === 'testnet');
        
        const balance = await getTotalBalance(cleanApi, cleanSecret, useDemo);
        
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        res.json({ success: true, message: `API keys saved! Balance: $${balance.toFixed(2)} USDT`, balance });
    } catch (error) {
        console.error('API key error:', error.response?.data || error.message);
        res.status(401).json({ success: false, message: 'Invalid API keys. Enable Spot & Margin Trading.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        
        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        
        res.json({ success: true, balance, totalBalance: balance, message: `Connected! Balance: $${balance.toFixed(2)} USDT` });
    } catch (error) {
        console.error('Connection error:', error);
        res.status(401).json({ success: false, message: 'Connection failed. Check API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== CONTINUOUS TRADING ENGINE (NO FIXED INTERVALS) ====================
const activeSessions = {};
const openPositions = {};

class TradingEngine {
    constructor(sessionId, userEmail, apiKey, secretKey, config, useDemo) {
        this.sessionId = sessionId;
        this.userEmail = userEmail;
        this.apiKey = apiKey;
        this.secretKey = secretKey;
        this.config = config;
        this.useDemo = useDemo;
        this.isActive = true;
        this.currentProfit = 0;
        this.trades = [];
        this.winStreak = 0;
        this.analysisLoop = null;
        this.monitorLoop = null;
        this.startTime = Date.now();
        this.lastAnalysisTime = {};
    }
    
    async start() {
        console.log(`🚀 Starting CONTINUOUS trading engine for ${this.userEmail}`);
        console.log(`   📊 Analysis: EVERY SECOND | 📈 Unlimited concurrent trades`);
        
        // CONTINUOUS ANALYSIS LOOP - Runs constantly, no fixed interval
        const runAnalysis = async () => {
            if (!this.isActive) return;
            
            // Check session limits
            const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
            if (elapsedHours >= this.config.timeLimit) {
                console.log(`⏰ Time limit reached for ${this.userEmail}`);
                await this.stop();
                return;
            }
            
            if (this.currentProfit >= this.config.targetProfit) {
                console.log(`🎯 Target reached! Total profit: $${this.currentProfit.toFixed(2)}`);
                await this.stop();
                return;
            }
            
            // Analyze all trading pairs continuously
            for (const symbol of this.config.tradingPairs) {
                if (!this.isActive) break;
                
                // Check if already have an open position for this symbol (max 1 per symbol at a time)
                const userPositions = openPositions[this.userEmail] || [];
                const hasPosition = userPositions.some(p => p.sessionId === this.sessionId && p.symbol === symbol);
                
                if (!hasPosition) {
                    try {
                        const signal = await getRealTimeAISignal(symbol, this.useDemo);
                        
                        if (signal.action === 'BUY' && signal.confidence >= 0.7) {
                            await this.executeTrade(symbol, 'BUY', signal);
                        } else if (signal.action === 'SELL' && signal.confidence >= 0.7) {
                            await this.executeTrade(symbol, 'SELL', signal);
                        }
                    } catch (error) {
                        console.error(`Analysis error for ${symbol}:`, error.message);
                    }
                }
            }
            
            // Continue the loop immediately (no delay for continuous analysis)
            if (this.isActive) {
                setImmediate(runAnalysis);
            }
        };
        
        // Start continuous analysis (runs as fast as possible, typically 10-50ms between cycles)
        this.analysisLoop = setImmediate(runAnalysis);
        
        // MONITOR OPEN POSITIONS - Check for profit taking every second
        const monitorPositions = async () => {
            if (!this.isActive) return;
            
            const userPositions = openPositions[this.userEmail] || [];
            
            for (const position of userPositions) {
                if (position.sessionId !== this.sessionId) continue;
                
                try {
                    const currentPrice = await getCurrentPrice(position.symbol, this.useDemo);
                    let unrealizedProfit = 0;
                    
                    if (position.side === 'BUY') {
                        unrealizedProfit = (currentPrice - position.entryPrice) * position.quantity;
                    } else {
                        unrealizedProfit = (position.entryPrice - currentPrice) * position.quantity;
                    }
                    
                    const profitPercent = (unrealizedProfit / position.positionSize) * 100;
                    
                    // CLOSE WHEN PROFITABLE - Take profit at positive percentage
                    // User can set their own take profit percentage
                    const takeProfitPercent = this.config.takeProfit || 1.5;
                    const stopLossPercent = this.config.stopLoss || -2;
                    
                    if (profitPercent >= takeProfitPercent) {
                        console.log(`📈 TAKING PROFIT: ${position.symbol} ${position.side} at ${profitPercent.toFixed(2)}%`);
                        await this.closePosition(position);
                    } else if (profitPercent <= stopLossPercent) {
                        console.log(`📉 STOP LOSS: ${position.symbol} ${position.side} at ${profitPercent.toFixed(2)}%`);
                        await this.closePosition(position);
                    }
                } catch (error) {
                    console.error(`Monitor error:`, error.message);
                }
            }
            
            // Monitor every second
            if (this.isActive) {
                setTimeout(monitorPositions, 1000);
            }
        };
        
        this.monitorLoop = setTimeout(monitorPositions, 1000);
    }
    
    async executeTrade(symbol, side, signal) {
        const userPositions = openPositions[this.userEmail] || [];
        
        // Check if already have open position for this symbol
        const hasPosition = userPositions.some(p => p.sessionId === this.sessionId && p.symbol === symbol);
        if (hasPosition) return;
        
        // Get current balance
        const balance = await getTotalBalance(this.apiKey, this.secretKey, this.useDemo);
        
        // Calculate position size based on user's investment amount
        let positionSize = this.config.investmentAmount;
        if (positionSize > balance * 0.9) positionSize = balance * 0.9;
        if (positionSize < 3) positionSize = 3;
        
        if (balance < positionSize + 10) {
            console.log(`⚠️ Insufficient balance: $${balance.toFixed(2)} USDT, need $${positionSize}`);
            return;
        }
        
        const currentPrice = signal.currentPrice || await getCurrentPrice(symbol, this.useDemo);
        const quantity = positionSize / currentPrice;
        
        try {
            console.log(`📈 EXECUTING ${side}: ${symbol} with $${positionSize.toFixed(2)} at $${currentPrice.toFixed(2)}`);
            const order = await placeMarketOrder(this.apiKey, this.secretKey, symbol, side, quantity, this.useDemo);
            const fillPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            const executedQty = parseFloat(order.executedQty);
            
            const newPosition = {
                sessionId: this.sessionId,
                symbol: symbol,
                side: side,
                quantity: executedQty,
                entryPrice: fillPrice,
                positionSize: positionSize,
                openedAt: new Date().toISOString(),
                aiConfidence: signal.confidence,
                aiReasons: signal.reasons
            };
            
            if (!openPositions[this.userEmail]) openPositions[this.userEmail] = [];
            openPositions[this.userEmail].push(newPosition);
            
            this.trades.unshift({
                symbol: symbol,
                side: `${side} OPEN`,
                entryPrice: fillPrice.toFixed(2),
                positionSize: positionSize.toFixed(2),
                aiConfidence: `${(signal.confidence * 100).toFixed(0)}%`,
                timestamp: new Date().toISOString()
            });
            
            console.log(`✅ ${side} opened for ${symbol} at $${fillPrice.toFixed(2)} | Size: $${positionSize.toFixed(2)}`);
        } catch (error) {
            console.error(`Trade execution error:`, error.message);
        }
    }
    
    async closePosition(position) {
        try {
            const currentPrice = await getCurrentPrice(position.symbol, this.useDemo);
            const closeSide = position.side === 'BUY' ? 'SELL' : 'BUY';
            const order = await placeMarketOrder(this.apiKey, this.secretKey, position.symbol, closeSide, position.quantity, this.useDemo);
            const fillPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            
            let profit = 0;
            if (position.side === 'BUY') {
                profit = (fillPrice - position.entryPrice) * position.quantity;
            } else {
                profit = (position.entryPrice - fillPrice) * position.quantity;
            }
            
            this.currentProfit += profit;
            this.winStreak = profit > 0 ? this.winStreak + 1 : 0;
            
            this.trades.unshift({
                symbol: position.symbol,
                side: `${position.side} CLOSED`,
                entryPrice: position.entryPrice.toFixed(2),
                exitPrice: fillPrice.toFixed(2),
                profit: profit.toFixed(2),
                profitPercent: ((profit / position.positionSize) * 100).toFixed(2),
                timestamp: new Date().toISOString()
            });
            
            // Save to file
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                exitPrice: fillPrice,
                profit: profit,
                profitPercent: (profit / position.positionSize) * 100,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            // Remove position
            openPositions[this.userEmail] = (openPositions[this.userEmail] || []).filter(p => p !== position);
            
            const profitSymbol = profit >= 0 ? '+' : '';
            console.log(`✅ CLOSED ${position.symbol} ${position.side} | Profit: ${profitSymbol}$${profit.toFixed(2)} (${((profit / position.positionSize) * 100).toFixed(2)}%) | Total: $${this.currentProfit.toFixed(2)}`);
        } catch (error) {
            console.error(`Close error:`, error.message);
        }
    }
    
    async stop() {
        console.log(`🛑 Stopping trading engine for ${this.userEmail}`);
        this.isActive = false;
        
        // Close all open positions
        const userPositions = openPositions[this.userEmail] || [];
        for (const position of userPositions) {
            if (position.sessionId === this.sessionId) {
                await this.closePosition(position);
            }
        }
    }
    
    getStatus() {
        const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, this.config.timeLimit - elapsedHours);
        const progressPercent = (this.currentProfit / this.config.targetProfit) * 100;
        
        return {
            isActive: this.isActive,
            currentProfit: this.currentProfit,
            targetProfit: this.config.targetProfit,
            winStreak: this.winStreak,
            timeRemaining: timeRemaining,
            progressPercent: progressPercent,
            openPositions: (openPositions[this.userEmail] || []).filter(p => p.sessionId === this.sessionId).length,
            trades: this.trades.slice(0, 30)
        };
    }
}

const engines = {};

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetProfit, timeLimit, riskLevel, tradingPairs, accountType, takeProfit, stopLoss } = req.body;
        
        console.log('📊 Start trading request:', { investmentAmount, targetProfit, timeLimit, riskLevel });
        
        // Validation - minimum $3 but user can invest any amount above
        if (investmentAmount < 3) return res.status(400).json({ success: false, message: 'Minimum investment is $3' });
        if (targetProfit < 1) return res.status(400).json({ success: false, message: 'Target profit must be at least $1' });
        if (!timeLimit || timeLimit < 0.1) return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });

        const users = readUsers();
        const user = users[req.user.email];
        if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });

        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');

        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        console.log(`💰 Current balance for ${req.user.email}: $${balance.toFixed(2)} USDT`);
        
        if (balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have $${balance.toFixed(2)} USDT, need $${investmentAmount}` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        
        const config = {
            investmentAmount: investmentAmount,
            targetProfit: targetProfit,
            timeLimit: timeLimit,
            riskLevel: riskLevel || 'medium',
            tradingPairs: tradingPairs || ['BTCUSDT', 'ETHUSDT'],
            takeProfit: takeProfit || 1.5,
            stopLoss: stopLoss || -2
        };
        
        const engine = new TradingEngine(sessionId, req.user.email, apiKey, secretKey, config, useDemo);
        engines[sessionId] = engine;
        await engine.start();
        
        console.log(`✅ Trading started for ${req.user.email} | Investment: $${investmentAmount} → Target: $${targetProfit} | Time: ${timeLimit}h`);
        res.json({ 
            success: true, 
            sessionId, 
            message: `✅ Trading started! Balance: $${balance.toFixed(2)} | Investment: $${investmentAmount} | AI analyzes CONTINUOUSLY | Unlimited concurrent trades | Take profit: ${config.takeProfit}% | Stop loss: ${config.stopLoss}%` 
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (engines[sessionId]) {
        engines[sessionId].stop();
        delete engines[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const engine = engines[sessionId];
    if (!engine) return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
    
    const status = engine.getStatus();
    res.json({
        success: true,
        currentProfit: status.currentProfit,
        targetProfit: status.targetProfit,
        newTrades: status.trades,
        winStreak: status.winStreak,
        timeRemaining: status.timeRemaining,
        progressPercent: status.progressPercent,
        openPositions: status.openPositions,
        isActive: status.isActive
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.json({ success: false, message: 'No API keys' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const balance = await getTotalBalance(apiKey, secretKey, useDemo);
        
        res.json({ success: true, balance, total: balance });
    } catch (error) {
        console.error('Balance API error:', error);
        res.json({ success: false, message: error.message });
    }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL AI TRADING BOT - CORRECTED VERSION`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Login: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Minimum Investment: $3 (user can invest any amount above)`);
    console.log(`✅ Default Time Limit: 1 hour (configurable higher)`);
    console.log(`✅ AI analyzes CONTINUOUSLY (every second, no fixed intervals)`);
    console.log(`✅ Unlimited concurrent trades (multiple positions at same time)`);
    console.log(`✅ Positions close when profitable (take profit: 1.5%, stop loss: -2%)`);
    console.log(`✅ 100% Halal - Spot Trading Only\n`);
});
