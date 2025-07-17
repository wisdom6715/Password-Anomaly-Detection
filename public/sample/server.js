const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');
const useragent = require('useragent');
const crypto = require('crypto');
const cors = require('cors')
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors())

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
        const userData = {
          username: this.username,
          email: this.email,
          password_hash: this.password_hash,
          phone_number: this.phone_number,
          is_active: this.is_active,
          failed_login_attempts: this.failed_login_attempts,
          created_at: new Date().toISOString()
        };

        const { data, error } = await supabase
          .from('users')
          .insert(userData)
          .select();

        if (error) throw error;
        
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
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
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
    this.device_type = data.device_type;
    this.browser = data.browser;
    this.os = data.os;

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
          device_type: this.device_type,
          browser: this.browser,
          os: this.os
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

  static async getStatsByUserId(userId) {
    try {
      const { data, error } = await supabase
        .from('login_attempts')
        .select('success')
        .eq('user_id', userId);

      if (error) throw error;

      const totalAttempts = data.length;
      const successfulLogins = data.filter(attempt => attempt.success).length;
      const failedAttempts = totalAttempts - successfulLogins;

      return {
        totalAttempts,
        successfulLogins,
        failedAttempts
      };
    } catch (error) {
      console.error(`Error getting login stats:`, error);
      return {
        totalAttempts: 0,
        successfulLogins: 0,
        failedAttempts: 0
      };
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

  static async getCountByUserId(userId) {
    try {
      const { data, error } = await supabase
        .from('threat_alerts')
        .select('id', { count: 'exact' })
        .eq('user_id', userId);

      if (error) throw error;
      return data.length;
    } catch (error) {
      console.error(`Error getting threat alerts count:`, error);
      return 0;
    }
  }
}

// Simple anomaly detection - detects if login from new IP
async function detectSimpleAnomaly(userId, ipAddress) {
  try {
    const { data, error } = await supabase
      .from('login_attempts')
      .select('ip_address')
      .eq('user_id', userId)
      .eq('success', true)
      .limit(10);

    if (error) throw error;

    const knownIps = data.map(attempt => attempt.ip_address);
    const isNewIp = !knownIps.includes(ipAddress);

    return isNewIp;
  } catch (error) {
    console.error('Error detecting anomaly:', error);
    return false;
  }
}

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

    const user = await User.getByUsername(username);

    if (user) {
      const passwordValid = await user.checkPassword(password);

      if (passwordValid) {
        // Successful login
        user.last_login = new Date().toISOString();
        user.failed_login_attempts = 0;
        await user.save();

        // Log successful login attempt
        const loginAttempt = await logLoginAttempt(user.id, user.username, true, req);

        // Simple anomaly detection - check if login from new IP
        const isAnomalous = await detectSimpleAnomaly(user.id, loginAttempt.ip_address);
        
        if (isAnomalous) {
          // Create threat alert
          const alert = new ThreatAlert({
            user_id: user.id,
            alert_type: 'new_ip_login',
            severity: 'medium',
            description: `Login from new IP address: ${loginAttempt.ip_address}`,
            ip_address: loginAttempt.ip_address,
            user_agent: loginAttempt.user_agent
          });
          await alert.save();

          // Send SMS alert
          const message = `🚨 Security Alert: Login from new IP address ${loginAttempt.ip_address}. If this wasn't you, please secure your account.`;
          const smsSent = await sendSmsAlert(user.phone_number, message);
        }

        // Generate JWT token
        const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET_KEY, { expiresIn: '24h' });

        const response = {
          message: 'Login successful',
          access_token: accessToken,
          user: user.toDict()
        };

        if (isAnomalous) {
          response.security_alert = 'New IP detected. SMS alert sent.';
        }

        return res.json(response);
      }
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

// NEW STATISTICS ENDPOINTS
app.get('/api/stats/login-attempts', authenticateToken, async (req, res) => {
  try {
    const stats = await LoginAttempt.getStatsByUserId(req.user.userId);
    res.json({
      total_login_attempts: stats.totalAttempts,
      successful_logins: stats.successfulLogins,
      failed_attempts: stats.failedAttempts
    });
  } catch (error) {
    console.error('Login stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/stats/security-alerts', authenticateToken, async (req, res) => {
  try {
    const alertsCount = await ThreatAlert.getCountByUserId(req.user.userId);
    res.json({
      security_alerts: alertsCount
    });
  } catch (error) {
    console.error('Security alerts stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/stats/dashboard', authenticateToken, async (req, res) => {
  try {
    const loginStats = await LoginAttempt.getStatsByUserId(req.user.userId);
    const alertsCount = await ThreatAlert.getCountByUserId(req.user.userId);
    
    res.json({
      total_login_attempts: loginStats.totalAttempts,
      successful_logins: loginStats.successfulLogins,
      failed_attempts: loginStats.failedAttempts,
      security_alerts: alertsCount
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// SMS Test endpoint
app.post('/api/test-sms', authenticateToken, async (req, res) => {
  try {
    const user = await User.getById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const testMessage = "🧪 Test SMS from your security system.";
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    twilio_configured: Boolean(twilioClient),
    supabase_configured: Boolean(supabase)
  });
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