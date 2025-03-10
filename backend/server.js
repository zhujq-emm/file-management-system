import express from 'express';
import fileUpload from 'express-fileupload';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import helmet from 'helmet';

// 初始化环境变量
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zhujq-emm-secret-key-2025';
const MAX_FILE_SIZE = process.env.MAX_FILE_SIZE || 50 * 1024 * 1024; // 50MB

// 安全配置
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 分钟
    max: 100 // 限制每个IP 15分钟内最多100个请求
});

// 中间件配置
app.use(helmet()); // 安全头
app.use(compression()); // GZIP压缩
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(limiter);
app.use(fileUpload({
    createParentPath: true,
    useTempFiles: true,
    tempFileDir: '/tmp/',
    debug: process.env.NODE_ENV === 'development',
    limits: { fileSize: MAX_FILE_SIZE },
    abortOnLimit: true
}));

// 定义路径
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const CATEGORIES_FILE = path.join(DATA_DIR, 'categories.json');

// 初始化目录和文件
async function initializeDirectories() {
    try {
        // 创建必要的目录
        await fs.mkdir(DATA_DIR, { recursive: true });
        await fs.mkdir(UPLOADS_DIR, { recursive: true });
        
        // 初始化用户数据
        try {
            await fs.access(USERS_FILE);
        } catch {
            const defaultAdmin = {
                username: "admin",
                password: await bcrypt.hash("admin123", 10),
                role: "admin",
                created: new Date().toISOString()
            };
            await fs.writeFile(USERS_FILE, JSON.stringify({
                "admin": defaultAdmin
            }, null, 2));
            console.log('Created default admin user');
        }
        
        // 初始化文件记录
        try {
            await fs.access(FILES_FILE);
        } catch {
            await fs.writeFile(FILES_FILE, JSON.stringify([], null, 2));
            console.log('Created files database');
        }
        
        // 初始化分类数据
        try {
            await fs.access(CATEGORIES_FILE);
        } catch {
            const defaultCategories = [
                { id: 'default', name: '默认分类', description: '默认分类' },
                { id: 'documents', name: '文档', description: '文档文件（DOC、PDF等）' },
                { id: 'images', name: '图片', description: '图片文件（JPG、PNG等）' },
                { id: 'videos', name: '视频', description: '视频文件（MP4、AVI等）' },
                { id: 'audio', name: '音频', description: '音频文件（MP3、WAV等）' },
                { id: 'archives', name: '压缩包', description: '压缩文件（ZIP、RAR等）' },
                { id: 'others', name: '其他', description: '其他类型文件' }
            ];
            await fs.writeFile(CATEGORIES_FILE, JSON.stringify(defaultCategories, null, 2));
            console.log('Created categories database');
        }
    } catch (error) {
        console.error('Initialization error:', error);
        process.exit(1);
    }
}

// 调用初始化函数
await initializeDirectories();

// 错误处理中间件
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        message: "服务器错误",
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
};

// 认证中间件
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ message: "未提供认证令牌" });
        }
        
        const user = jwt.verify(token, JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ message: "无效的认证令牌" });
    }
};

// 管理员权限中间件
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "需要管理员权限" });
    }
    next();
};

// 用户认证路由
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ message: "用户名和密码不能为空" });
        }

        const users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
        const user = users[username];
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "用户名或密码错误" });
        }
        
        const token = jwt.sign(
            { 
                username: user.username, 
                role: user.role,
                iat: Math.floor(Date.now() / 1000)
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            role: user.role,
            expiresIn: 24 * 60 * 60 * 1000
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: "登录失败" });
    }
});

// 用户注册路由
app.post('/api/register', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        if (!username || !password || !role) {
            return res.status(400).json({ message: "所有字段都是必填的" });
        }

        if (username.length < 3 || password.length < 6) {
            return res.status(400).json({ 
                message: "用户名至少3个字符，密码至少6个字符" 
            });
        }

        const users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
        
        if (users[username]) {
            return res.status(400).json({ message: "用户名已存在" });
        }
        
        users[username] = {
            username,
            password: await bcrypt.hash(password, 10),
            role,
            created: new Date().toISOString(),
            createdBy: req.user.username
        };
        
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        res.status(201).json({ message: "用户创建成功" });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ message: "用户注册失败" });
    }
});

// 获取分类列表
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const categories = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8'));
        res.json(categories);
    } catch (err) {
        console.error('Get categories error:', err);
        res.status(500).json({ message: "获取分类列表失败" });
    }
});

// 创建新分类
app.post('/api/categories', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, description } = req.body;
        
        if (!name || !description) {
            return res.status(400).json({ message: "分类名称和描述不能为空" });
        }

        const categories = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8'));
        
        const newCategory = {
            id: name.toLowerCase().replace(/\s+/g, '-'),
            name,
            description,
            created: new Date().toISOString(),
            createdBy: req.user.username
        };
        
        if (categories.find(c => c.id === newCategory.id)) {
            return res.status(400).json({ message: "分类已存在" });
        }
        
        categories.push(newCategory);
        await fs.writeFile(CATEGORIES_FILE, JSON.stringify(categories, null, 2));
        res.status(201).json(newCategory);
    } catch (err) {
        console.error('Create category error:', err);
        res.status(500).json({ message: "创建分类失败" });
    }
});

// 获取文件列表
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const files = JSON.parse(await fs.readFile(FILES_FILE, 'utf8'));
        res.json(files);
    } catch (err) {
        console.error('Get files error:', err);
        res.status(500).json({ message: "获取文件列表失败" });
    }
});

// 上传文件
app.post('/api/upload', authenticateToken, isAdmin, async (req, res) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).json({ message: "没有选择文件" });
        }

        const file = req.files.file;
        const category = req.body.category || 'default';
        const timestamp = Date.now();
        const safeName = `${timestamp}-${file.name.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
        const filePath = path.join(UPLOADS_DIR, safeName);

        // 检查分类是否存在
        const categories = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8'));
        if (!categories.find(c => c.id === category)) {
            return res.status(400).json({ message: "无效的分类" });
        }

        await file.mv(filePath);

        const files = JSON.parse(await fs.readFile(FILES_FILE, 'utf8'));
        const fileRecord = {
            id: timestamp.toString(),
            name: safeName,
            originalName: file.name,
            uploadedBy: req.user.username,
            uploadDate: new Date().toISOString(),
            size: file.size,
            type: file.mimetype,
            category: category
        };
        
        files.push(fileRecord);
        await fs.writeFile(FILES_FILE, JSON.stringify(files, null, 2));

        res.status(201).json({ 
            message: "文件上传成功",
            file: fileRecord
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ message: "文件上传失败" });
    }
});

// 下载文件
app.get('/api/download/:filename', authenticateToken, async (req, res) => {
    try {
        const filePath = path.join(UPLOADS_DIR, req.params.filename);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ message: "文件不存在" });
        }

        const files = JSON.parse(await fs.readFile(FILES_FILE, 'utf8'));
        const fileRecord = files.find(f => f.name === req.params.filename);
        
        if (!fileRecord) {
            return res.status(404).json({ message: "文件记录不存在" });
        }

        res.download(filePath, fileRecord.originalName);
    } catch (err) {
        console.error('Download error:', err);
        res.status(500).json({ message: "文件下载失败" });
    }
});

// 删除文件
app.delete('/api/files/:filename', authenticateToken, isAdmin, async (req, res) => {
    try {
        const filePath = path.join(UPLOADS_DIR, req.params.filename);
        const files = JSON.parse(await fs.readFile(FILES_FILE, 'utf8'));
        
        const fileIndex = files.findIndex(f => f.name === req.params.filename);
        if (fileIndex === -1) {
            return res.status(404).json({ message: "文件不存在" });
        }
        
        try {
            await fs.unlink(filePath);
        } catch (err) {
            console.error('File deletion error:', err);
        }

        files.splice(fileIndex, 1);
        await fs.writeFile(FILES_FILE, JSON.stringify(files, null, 2));
        
        res.json({ message: "文件删除成功" });
    } catch (err) {
        console.error('Delete file error:', err);
        res.status(500).json({ message: "文件删除失败" });
    }
});

// 错误处理中间件
app.use(errorHandler);

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
    console.log('环境:', process.env.NODE_ENV || 'development');
    console.log('初始管理员账号：admin');
    console.log('初始管理员密码：admin123');
});

// 优雅关闭
process.on('SIGTERM', () => {
    console.log('收到 SIGTERM 信号，准备关闭服务器');
    server.close(() => {
        console.log('服务器已关闭');
        process.exit(0);
    });
});