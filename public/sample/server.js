const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');
const useragent = require('useragent');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

// Configuration
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || 'jwt-secret-string';

// Supabase Configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Twilio Configuration
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

console.log(`Twilio configured: ${Boolean(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN)}`);

const twilioClient = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN 
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) 
  : null;

// Database Helper Classes
class User {
  constructor(data = {}) {
    this.id = data.id;
    this.username = data.username;
    this.email = data.email;
    this.password_hash = data.password_hash;
    this.phone_number = data.phone_number;
    this.created_at = data.created_at;
    this.is_active = data.is_active ?? true;
    this.failed_login_attempts = data.failed_login_attempts ?? 0;
    this.last_login = data.last_login;
  }

  async setPassword(password) {
    this.password_hash = await bcrypt.hash(password, 12);
  }

  async checkPassword(password) {
    return await bcrypt.compare(password, this.password_hash);
  }

  toDict() {
    return {
      id: this.id,
      username: this.username,
      email: this.email,
      phone_number: this.phone_number,
      created_at: this.created_at,
      last_login: this.last_login
    };
  }

  async save() {
    try {
      if (this.id) {
        // Update existing user
        const { data, error } = await supabase
          .from('users')
          .update({
            username: this.username,
            email: this.email,
            password_hash: this.password_hash,
            phone_number: this.phone_number,
            is_active: this.is_active,
            failed_login_attempts: this.failed_login_attempts,
            last_login: this.last_login
          })
          .eq('id', this.id)
          .select();

        if (error) throw error;
      } else {
        // Create new user
        const userData = {
          username: this.username,
          email: this.email,
          password_hash: this.password_hash,
          phone_number: this.phone_number,
          is_active: this.is_active,
          failed_login_attempts: this.failed_login_attempts,
          created_at: new Date().toISOString()
        };

        console.log(`Creating user with data:`, userData);
        const { data, error } = await supabase
          .from('users')
          .insert(userData)
          .select();

        if (error) throw error;
        console.log(`Insert result:`, data);
        
        if (data && data.length > 0) {
          this.id = data[0].id;
        }
      }
      return this;
    } catch (error) {
      console.error(`Error saving user:`, error);
      throw error;
    }
  }

  static async getByUsername(username) {
    try {
      console.log(`Querying user with username: ${username}`);
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      console.log(`Query result:`, data);
      
      return data ? new User(data) : null;
    } catch (error) {
      console.error(`Error getting user by username:`, error);
      return null;
    }
  }

  static async getByEmail(email) {
    try {
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      return data ? new User(data) : null;
    } catch (error) {
      console.error(`Error getting user by email:`, error);
      return null;
    }
  }

  static async getById(userId) {
    try {
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      return data ? new User(data) : null;
    } catch (error) {
      console.error(`Error getting user by ID:`, error);
      return null;
    }
  }
}

class LoginAttempt {
  constructor(data = {}) {
    this.id = data.id;
    this.user_id = data.user_id;
    this.username = data.username;
    this.ip_address = data.ip_address;
    this.user_agent = data.user_agent;
    this.success = data.success;
    this.timestamp = data.timestamp || new Date();
    this.location_country = data.location_country;
    this.location_city = data.location_city;
    this.device_type = data.device_type;
    this.browser = data.browser;
    this.os = data.os;
    this.hour_of_day = data.hour_of_day;
    this.day_of_week = data.day_of_week;

    // Parse user agent if not already parsed
    if (this.user_agent && !this.device_type) {
      this.parseUserAgent();
    }
  }

  parseUserAgent() {
    const agent = useragent.parse(this.user_agent);
    this.device_type = agent.device.family;
    this.browser = agent.family;
    this.os = agent.os.family;

    // Set time-based attributes
    const timestamp = new Date(this.timestamp);
    this.hour_of_day = timestamp.getHours();
    this.day_of_week = timestamp.getDay();
  }

  async save() {
    try {
      const timestampStr = this.timestamp instanceof Date 
        ? this.timestamp.toISOString() 
        : this.timestamp;

      const { data, error } = await supabase
        .from('login_attempts')
        .insert({
          user_id: this.user_id,
          username: this.username,
          ip_address: this.ip_address,
          user_agent: this.user_agent,
          success: this.success,
          timestamp: timestampStr,
          location_country: this.location_country,
          location_city: this.location_city,
          device_type: this.device_type,
          browser: this.browser,
          os: this.os,
          hour_of_day: this.hour_of_day,
          day_of_week: this.day_of_week
        })
        .select();

      if (error) throw error;
      if (data && data.length > 0) {
        this.id = data[0].id;
      }
      return this;
    } catch (error) {
      console.error(`Error saving login attempt:`, error);
      throw error;
    }
  }

  static async getByUserId(userId, limit = null) {
    try {
      let query = supabase
        .from('login_attempts')
        .select('*')
        .eq('user_id', userId)
        .order('timestamp', { ascending: false });

      if (limit) {
        query = query.limit(limit);
      }

      const { data, error } = await query;
      if (error) throw error;

      return data.map(attempt => new LoginAttempt(attempt));
    } catch (error) {
      console.error(`Error getting login attempts:`, error);
      return [];
    }
  }
}

class ThreatAlert {
  constructor(data = {}) {
    this.id = data.id;
    this.user_id = data.user_id;
    this.alert_type = data.alert_type;
    this.severity = data.severity;
    this.description = data.description;
    this.timestamp = data.timestamp || new Date();
    this.sms_sent = data.sms_sent || false;
    this.ip_address = data.ip_address;
    this.user_agent = data.user_agent;
  }

  async save() {
    try {
      const timestampStr = this.timestamp instanceof Date 
        ? this.timestamp.toISOString() 
        : this.timestamp;

      const { data, error } = await supabase
        .from('threat_alerts')
        .insert({
          user_id: this.user_id,
          alert_type: this.alert_type,
          severity: this.severity,
          description: this.description,
          timestamp: timestampStr,
          sms_sent: this.sms_sent,
          ip_address: this.ip_address,
          user_agent: this.user_agent
        })
        .select();

      if (error) throw error;
      if (data && data.length > 0) {
        this.id = data[0].id;
      }
      return this;
    } catch (error) {
      console.error(`Error saving threat alert:`, error);
      throw error;
    }
  }

  async updateSmsSent(smsSent) {
    try {
      this.sms_sent = smsSent;
      if (this.id) {
        const { error } = await supabase
          .from('threat_alerts')
          .update({ sms_sent: smsSent })
          .eq('id', this.id);

        if (error) throw error;
      }
    } catch (error) {
      console.error(`Error updating SMS sent status:`, error);
    }
  }

  static async getByUserId(userId, limit = 50) {
    try {
      const { data, error } = await supabase
        .from('threat_alerts')
        .select('*')
        .eq('user_id', userId)
        .order('timestamp', { ascending: false })
        .limit(limit);

      if (error) throw error;
      return data.map(alert => new ThreatAlert(alert));
    } catch (error) {
      console.error(`Error getting threat alerts:`, error);
      return [];
    }
  }
}

// Anomaly Detection Class
class AnomalyDetector {
  constructor() {
    this.model = null;
    this.scaler = null;
    this.isTrained = false;
    this.contamination = 0.1;
  }

  extractFeatures(loginAttempts) {
    return loginAttempts.map(attempt => [
      attempt.hour_of_day,
      attempt.day_of_week,
      attempt.ip_address.length,
      this.hashString(attempt.ip_address) % 1000,
      this.hashString(attempt.user_agent) % 1000,
      attempt.success ? 1 : 0,
      this.hashString(attempt.device_type || '') % 100,
      this.hashString(attempt.browser || '') % 100,
      this.hashString(attempt.os || '') % 100
    ]);
  }

  hashString(str) {
    return crypto.createHash('md5').update(str).digest('hex')
      .split('')
      .reduce((acc, char) => acc + char.charCodeAt(0), 0);
  }

  async train(userId) {
    try {
      const attempts = await LoginAttempt.getByUserId(userId);
      
      if (attempts.length < 10) {
        return false;
      }

      const features = this.extractFeatures(attempts);
      
      // Simple anomaly detection using statistical methods
      this.model = this.calculateBaseline(features);
      this.isTrained = true;
      return true;
    } catch (error) {
      console.error(`Error training model:`, error);
      return false;
    }
  }

  calculateBaseline(features) {
    const means = [];
    const stds = [];
    
    for (let i = 0; i < features[0].length; i++) {
      const column = features.map(row => row[i]);
      const mean = column.reduce((sum, val) => sum + val, 0) / column.length;
      const variance = column.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / column.length;
      const std = Math.sqrt(variance);
      
      means.push(mean);
      stds.push(std || 1); // Prevent division by zero
    }
    
    return { means, stds };
  }

  detectAnomaly(loginAttempt) {
    if (!this.isTrained) {
      return { isAnomaly: false, score: 0.0 };
    }

    const features = this.extractFeatures([loginAttempt])[0];
    let anomalyScore = 0;
    
    // Calculate z-score for each feature
    for (let i = 0; i < features.length; i++) {
      const zScore = Math.abs((features[i] - this.model.means[i]) / this.model.stds[i]);
      anomalyScore += zScore;
    }
    
    // Normalize score
    anomalyScore = anomalyScore / features.length;
    
    // Consider anomalous if average z-score > 2
    const isAnomaly = anomalyScore > 2;
    
    return { isAnomaly, score: anomalyScore };
  }
}

// Global anomaly detector instance
const anomalyDetector = new AnomalyDetector();

// Helper Functions
async function sendSmsAlert(phoneNumber, message) {
  if (!twilioClient) {
    console.log(`⚠️  Twilio not configured. SMS would be sent to ${phoneNumber}: ${message}`);
    return false;
  }

  try {
    if (!phoneNumber.startsWith('+')) {
      console.log("❌ Phone number is not in E.234 format.");
      return false;
    }

    const messageObj = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });

    console.log(`✅ SMS sent to ${phoneNumber}, SID: ${messageObj.sid}`);
    return true;
  } catch (error) {
    console.error(`❌ SMS sending failed:`, error);
    return false;
  }
}

function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress;
}

async function logLoginAttempt(userId, username, success, req) {
  const ipAddress = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  const attempt = new LoginAttempt({
    user_id: userId,
    username: username,
    ip_address: ipAddress,
    user_agent: userAgent,
    success: success
  });

  await attempt.save();
  return attempt;
}

async function checkForAnomalies(userId, loginAttempt) {
  console.log(`🔍 Checking for anomalies for user ${userId}`);

  // Train model if not already trained
  if (!anomalyDetector.isTrained) {
    console.log("🤖 Training anomaly detection model...");
    const trainingSuccess = await anomalyDetector.train(userId);
    if (trainingSuccess) {
      console.log("✅ Model trained successfully");
    } else {
      console.log("⚠️  Insufficient data for training (need at least 10 login attempts)");
      return false;
    }
  }

  // Detect anomaly
  const { isAnomaly, score } = anomalyDetector.detectAnomaly(loginAttempt);
  console.log(`🎯 Anomaly detection result: ${isAnomaly}, Score: ${score.toFixed(2)}`);

  if (isAnomaly) {
    console.log("🚨 ANOMALY DETECTED! Sending alert...");
    const user = await User.getById(userId);
    if (user) {
      // Create threat alert
      const alert = new ThreatAlert({
        user_id: userId,
        alert_type: 'login_anomaly',
        severity: 'medium',
        description: `Anomalous login detected from IP: ${loginAttempt.ip_address}. Anomaly score: ${score.toFixed(2)}`,
        ip_address: loginAttempt.ip_address,
        user_agent: loginAttempt.user_agent
      });
      await alert.save();

      // Send SMS alert
      const message = `🚨 Security Alert: Unusual login activity detected on your account from ${loginAttempt.ip_address}. If this wasn't you, please secure your account immediately.`;
      const smsSent = await sendSmsAlert(user.phone_number, message);
      await alert.updateSmsSent(smsSent);

      console.log(`📧 Alert created and SMS sent: ${smsSent}`);
      return true;
    }
  } else {
    console.log("✅ Login appears normal");
  }

  return false;
}

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// API Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, phone_number } = req.body;

    // Validate required fields
    const requiredFields = ['username', 'email', 'password', 'phone_number'];
    for (const field of requiredFields) {
      if (!req.body[field]) {
        return res.status(400).json({ error: `${field} is required` });
      }
    }

    // Check if user already exists
    const existingUser = await User.getByUsername(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const existingEmail = await User.getByEmail(email);
    if (existingEmail) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    // Create new user
    const user = new User({
      username,
      email,
      phone_number
    });
    await user.setPassword(password);
    await user.save();

    res.status(201).json({
      message: 'User registered successfully',
      user: user.toDict()
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    console.log(`Login attempt for username: ${username}`);
    const user = await User.getByUsername(username);

    if (user) {
      console.log(`User found: ${user.username}`);
      const passwordValid = await user.checkPassword(password);
      console.log(`Password check result: ${passwordValid}`);

      if (passwordValid) {
        // Successful login
        user.last_login = new Date().toISOString();
        user.failed_login_attempts = 0;
        await user.save();

        // Log successful login attempt
        const loginAttempt = await logLoginAttempt(user.id, user.username, true, req);

        // Check for anomalies
        const anomalyDetected = await checkForAnomalies(user.id, loginAttempt);

        // Generate JWT token
        const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET_KEY, { expiresIn: '24h' });

        const response = {
          message: 'Login successful',
          access_token: accessToken,
          user: user.toDict()
        };

        if (anomalyDetected) {
          response.security_alert = 'Unusual activity detected. SMS alert sent.';
        }

        return res.json(response);
      }
    } else {
      console.log("User not found");
    }

    // Failed login
    if (user) {
      user.failed_login_attempts += 1;
      await user.save();
      await logLoginAttempt(user.id, username, false, req);
    } else {
      await logLoginAttempt(null, username, false, req);
    }

    res.status(401).json({ error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.getById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user.toDict());
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/security/alerts', authenticateToken, async (req, res) => {
  try {
    const alerts = await ThreatAlert.getByUserId(req.user.userId, 50);

    const alertsData = alerts.map(alert => {
      let timestamp = alert.timestamp;
      if (typeof timestamp === 'string') {
        timestamp = new Date(timestamp.replace('Z', '+00:00')).toISOString();
      } else if (timestamp instanceof Date) {
        timestamp = timestamp.toISOString();
      }

      return {
        id: alert.id,
        alert_type: alert.alert_type,
        severity: alert.severity,
        description: alert.description,
        timestamp: timestamp,
        sms_sent: alert.sms_sent,
        ip_address: alert.ip_address
      };
    });

    res.json(alertsData);
  } catch (error) {
    console.error('Security alerts error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/security/login-history', authenticateToken, async (req, res) => {
  try {
    const attempts = await LoginAttempt.getByUserId(req.user.userId, 100);

    const history = attempts.map(attempt => {
      let timestamp = attempt.timestamp;
      if (typeof timestamp === 'string') {
        timestamp = new Date(timestamp.replace('Z', '+00:00')).toISOString();
      } else if (timestamp instanceof Date) {
        timestamp = timestamp.toISOString();
      }

      return {
        ip_address: attempt.ip_address,
        success: attempt.success,
        timestamp: timestamp,
        device_type: attempt.device_type,
        browser: attempt.browser,
        os: attempt.os,
        location_country: attempt.location_country,
        location_city: attempt.location_city
      };
    });

    res.json(history);
  } catch (error) {
    console.error('Login history error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/security/retrain-model', authenticateToken, async (req, res) => {
  try {
    const success = await anomalyDetector.train(req.user.userId);

    if (success) {
      res.json({ message: 'Model retrained successfully' });
    } else {
      res.status(400).json({ error: 'Insufficient data for training' });
    }
  } catch (error) {
    console.error('Retrain model error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    twilio_configured: Boolean(twilioClient),
    supabase_configured: Boolean(supabase)
  });
});

app.post('/api/test-sms', authenticateToken, async (req, res) => {
  try {
    const user = await User.getById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const testMessage = "🧪 Test SMS from your security system. This is just for testing your project please kindly ignore from wisdom.A";
    const success = await sendSmsAlert(user.phone_number, testMessage);

    res.json({
      message: 'SMS test completed',
      success: success,
      twilio_configured: Boolean(twilioClient)
    });
  } catch (error) {
    console.error('Test SMS error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handlers
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});