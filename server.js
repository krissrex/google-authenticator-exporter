const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const qr = require('qrcode-reader');
const Jimp = require('jimp');
const { decodeExportUri } = require('./src/index');

const app = express();
const PORT = 3000;

// 中间件
app.use(fileUpload());
app.use(express.static('public'));

// API路由
app.post('/api/process-qr', async (req, res) => {
    try {
        if (!req.files || !req.files.qrImage) {
            return res.status(400).json({ error: '未上传文件' });
        }

        const qrImage = req.files.qrImage;
        const tempPath = path.join(__dirname, 'temp', qrImage.name);
        
        // 确保temp目录存在
        if (!fs.existsSync(path.join(__dirname, 'temp'))) {
            fs.mkdirSync(path.join(__dirname, 'temp'));
        }
        
        // 保存临时文件
        await qrImage.mv(tempPath);
        
        // 读取并解析QR码
        const image = await Jimp.Jimp.read(fs.readFileSync(tempPath));
        const qrCode = new qr();
        
        const value = await new Promise((resolve, reject) => {
            qrCode.callback = (err, v) => err ? reject(err) : resolve(v);
            qrCode.decode(image.bitmap);
        });
        
        // 删除临时文件
        fs.unlinkSync(tempPath);
        
        // 解析密钥
        const accounts = decodeExportUri(value.result);
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
});