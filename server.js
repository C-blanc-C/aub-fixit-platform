// server.js - Main backend server file
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// Initialize SQLite database
const db = new sqlite3.Database('./fixit.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'student',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Issues table
    db.run(`CREATE TABLE IF NOT EXISTS issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        building TEXT NOT NULL,
        location TEXT NOT NULL,
        urgency TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'open',
        reporter_id INTEGER,
        anonymous BOOLEAN DEFAULT 0,
        image_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (reporter_id) REFERENCES users (id)
    )`);

    // Upvotes table
    db.run(`CREATE TABLE IF NOT EXISTS upvotes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (issue_id) REFERENCES issues (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(issue_id, user_id)
    )`);

    // Comments table
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (issue_id) REFERENCES issues (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Issue updates table (for tracking status changes)
    db.run(`CREATE TABLE IF NOT EXISTS issue_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (issue_id) REFERENCES issues (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                
                const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
                res.json({ token, user: { id: this.lastID, username, email } });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, username],
        async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
            res.json({ 
                token, 
                user: { 
                    id: user.id, 
                    username: user.username, 
                    email: user.email,
                    role: user.role 
                } 
            });
        }
    );
});

// Get all issues with upvote counts
app.get('/api/issues', (req, res) => {
    const { status, category, building } = req.query;
    let query = `
        SELECT 
            i.*,
            u.username as reporter_name,
            COUNT(DISTINCT uv.id) as upvotes,
            COUNT(DISTINCT c.id) as comments
        FROM issues i
        LEFT JOIN users u ON i.reporter_id = u.id
        LEFT JOIN upvotes uv ON i.id = uv.issue_id
        LEFT JOIN comments c ON i.id = c.issue_id
        WHERE 1=1
    `;
    
    const params = [];
    
    if (status) {
        query += ' AND i.status = ?';
        params.push(status);
    }
    
    if (category) {
        query += ' AND i.category = ?';
        params.push(category);
    }
    
    if (building) {
        query += ' AND i.building = ?';
        params.push(building);
    }
    
    query += ' GROUP BY i.id ORDER BY i.created_at DESC';
    
    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        // Hide reporter info if anonymous
        rows = rows.map(row => {
            if (row.anonymous) {
                row.reporter_name = 'Anonymous';
                delete row.reporter_id;
            }
            return row;
        });
        
        res.json(rows);
    });
});

// Get single issue with details
app.get('/api/issues/:id', (req, res) => {
    const issueId = req.params.id;
    
    // Get issue details
    db.get(`
        SELECT 
            i.*,
            u.username as reporter_name,
            COUNT(DISTINCT uv.id) as upvotes
        FROM issues i
        LEFT JOIN users u ON i.reporter_id = u.id
        LEFT JOIN upvotes uv ON i.id = uv.issue_id
        WHERE i.id = ?
        GROUP BY i.id
    `, [issueId], (err, issue) => {
        if (err || !issue) {
            return res.status(404).json({ error: 'Issue not found' });
        }
        
        // Get comments
        db.all(`
            SELECT c.*, u.username
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.issue_id = ?
            ORDER BY c.created_at DESC
        `, [issueId], (err, comments) => {
            if (err) comments = [];
            
            // Get status updates
            db.all(`
                SELECT iu.*, u.username
                FROM issue_updates iu
                JOIN users u ON iu.user_id = u.id
                WHERE iu.issue_id = ?
                ORDER BY iu.created_at DESC
            `, [issueId], (err, updates) => {
                if (err) updates = [];
                
                // Hide reporter info if anonymous
                if (issue.anonymous) {
                    issue.reporter_name = 'Anonymous';
                    delete issue.reporter_id;
                }
                
                res.json({
                    ...issue,
                    comments,
                    updates
                });
            });
        });
    });
});

// Create new issue
app.post('/api/issues', authenticateToken, upload.single('image'), (req, res) => {
    const { title, description, category, building, location, urgency, anonymous } = req.body;
    const reporter_id = req.user.id;
    const image_path = req.file ? req.file.path : null;
    
    db.run(`
        INSERT INTO issues (title, description, category, building, location, urgency, reporter_id, anonymous, image_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [title, description, category, building, location, urgency, reporter_id, anonymous === 'true', image_path],
    function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to create issue' });
        }
        
        res.json({ id: this.lastID, message: 'Issue created successfully' });
    });
});

// Update issue status (admin/maintenance staff only)
app.put('/api/issues/:id/status', authenticateToken, (req, res) => {
    const { status, notes } = req.body;
    const issueId = req.params.id;
    
    // Get current status
    db.get('SELECT status FROM issues WHERE id = ?', [issueId], (err, issue) => {
        if (err || !issue) {
            return res.status(404).json({ error: 'Issue not found' });
        }
        
        const oldStatus = issue.status;
        
        // Update issue status
        db.run(
            'UPDATE issues SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [status, issueId],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update status' });
                }
                
                // Log the status change
                db.run(`
                    INSERT INTO issue_updates (issue_id, user_id, old_status, new_status, notes)
                    VALUES (?, ?, ?, ?, ?)
                `, [issueId, req.user.id, oldStatus, status, notes], (err) => {
                    if (err) console.error('Failed to log status update:', err);
                });
                
                res.json({ message: 'Status updated successfully' });
            }
        );
    });
});

// Upvote/remove upvote
app.post('/api/issues/:id/upvote', authenticateToken, (req, res) => {
    const issueId = req.params.id;
    const userId = req.user.id;
    
    // Check if already upvoted
    db.get(
        'SELECT id FROM upvotes WHERE issue_id = ? AND user_id = ?',
        [issueId, userId],
        (err, upvote) => {
            if (upvote) {
                // Remove upvote
                db.run(
                    'DELETE FROM upvotes WHERE issue_id = ? AND user_id = ?',
                    [issueId, userId],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Failed to remove upvote' });
                        }
                        res.json({ upvoted: false });
                    }
                );
            } else {
                // Add upvote
                db.run(
                    'INSERT INTO upvotes (issue_id, user_id) VALUES (?, ?)',
                    [issueId, userId],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Failed to add upvote' });
                        }
                        res.json({ upvoted: true });
                    }
                );
            }
        }
    );
});

// Add comment
app.post('/api/issues/:id/comments', authenticateToken, (req, res) => {
    const { comment } = req.body;
    const issueId = req.params.id;
    const userId = req.user.id;
    
    db.run(
        'INSERT INTO comments (issue_id, user_id, comment) VALUES (?, ?, ?)',
        [issueId, userId, comment],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to add comment' });
            }
            
            res.json({ id: this.lastID, message: 'Comment added successfully' });
        }
    );
});

// Get statistics
app.get('/api/statistics', (req, res) => {
    const stats = {};
    
    // Total issues
    db.get('SELECT COUNT(*) as total FROM issues', (err, row) => {
        stats.total = row.total;
        
        // Issues by status
        db.all('SELECT status, COUNT(*) as count FROM issues GROUP BY status', (err, rows) => {
            stats.byStatus = rows;
            
            // Issues by category
            db.all('SELECT category, COUNT(*) as count FROM issues GROUP BY category', (err, rows) => {
                stats.byCategory = rows;
                
                // Issues by building
                db.all('SELECT building, COUNT(*) as count FROM issues GROUP BY building', (err, rows) => {
                    stats.byBuilding = rows;
                    
                    // Average resolution time (for resolved issues)
                    db.get(`
                        SELECT AVG(julianday(updated_at) - julianday(created_at)) as avgDays
                        FROM issues
                        WHERE status = 'resolved'
                    `, (err, row) => {
                        stats.avgResolutionDays = row.avgDays || 0;
                        
                        res.json(stats);
                    });
                });
            });
        });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Gracefully close database connection on exit
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});