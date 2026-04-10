#!/usr/bin/env node
/**
 * flood.js – CI‑friendly UDP / HTTP / HTTPS load generator (pure Node.js)
 * - 精准速率控制（令牌桶）
 * - 共享内存计数
 * - 阈值检测 → 退出码 0/2/1
 * - 新增 --quiet / -q 选项（不打印任何报告）
 * - 支持 CLI / ENV / JSON 配置
 *
 * 作者: Minearm‑RPM（原始脚本） + ChatGPT 2024‑06 改进
 */

'use strict';

// ---------- Node 内置 ----------
const {
  Worker,
  isMainThread,
  parentPort,
  workerData,
  threadId,
} = require('worker_threads');
const os = require('os');
const crypto = require('crypto');
const readline = require('readline');
const { argv, exit, stdout, env } = process;
const fs = require('fs');
const path = require('path');

// ---------- 默认值 ----------
const DEFAULTS = {
  protocol: 'udp',
  rate: 1000,
  time: 10,
  threads: os.cpus().length,
  size: 1400,
  minSent: 0,
  maxFail: Infinity,
  minRate: 0,
  output: 'json',
  quiet: false,
};

// ---------- 参数解析 ----------
function parseCli() {
  const args = {};

  // JSON 配置文件（如果使用 --config <file>）
  const cfgIdx = argv.findIndex((v) => v === '--config' || v === '-cfile');
  if (cfgIdx !== -1 && argv[cfgIdx + 1]) {
    try {
      const cfg = JSON.parse(fs.readFileSync(path.resolve(argv[cfgIdx + 1]), 'utf8'));
      Object.assign(args, cfg);
    } catch (e) {
      console.error(`读取配置文件失败: ${e.message}`);
      exit(2);
    }
  }

  // CLI 选项
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-i':
      case '--ip':
        args.ip = argv[++i];
        break;
      case '-p':
      case '--port':
        args.port = Number(argv[++i]);
        break;
      case '-r':
      case '--rate':
        args.rate = Number(argv[++i]);
        break;
      case '-t':
      case '--time':
        args.time = Number(argv[++i]);
        break;
      case '-C':
      case '--threads':
        args.threads = Number(argv[++i]);
        break;
      case '-s':
      case '--size':
        args.size = Number(argv[++i]);
        break;
      case '-P':
      case '--protocol':
        args.protocol = argv[++i].toLowerCase();
        break;
      case '--min-sent':
        args.minSent = Number(argv[++i]);
        break;
      case '--max-fail':
        args.maxFail = Number(argv[++i]);
        break;
      case '--min-rate':
        args.minRate = Number(argv[++i]);
        break;
      case '--output':
        args.output = argv[++i].toLowerCase();
        break;
      case '-q':
      case '--quiet':
        args.quiet = true;
        break;
      case '-h':
      case '--help':
        return null;
      default:
        console.error(`未知参数: ${a}`);
        return null;
    }
  }

  // 环境变量（最低优先级）
  const envMap = {
    ip: env.FLOOD_IP,
    port: env.FLOOD_PORT && Number(env.FLOOD_PORT),
    protocol: env.FLOOD_PROTO,
    rate: env.FLOOD_RATE && Number(env.FLOOD_RATE),
    time: env.FLOOD_TIME && Number(env.FLOOD_TIME),
    threads: env.FLOOD_THREADS && Number(env.FLOOD_THREADS),
    size: env.FLOOD_SIZE && Number(env.FLOOD_SIZE),
    minSent: env.FLOOD_MIN_SENT && Number(env.FLOOD_MIN_SENT),
    maxFail: env.FLOOD_MAX_FAIL && Number(env.FLOOD_MAX_FAIL),
    minRate: env.FLOOD_MIN_RATE && Number(env.FLOOD_MIN_RATE),
    output: env.FLOOD_OUTPUT,
    quiet: env.FLOOD_QUIET === 'true',
  };
  Object.entries(envMap).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') args[k] = v;
  });

  return args;
}

// ---------- 帮助 ----------
function printHelp() {
  const help = `
flood.js – 多协议压测工具（纯 Node.js）

  node flood.js [options]

选项:
  -i, --ip <host>           目标 IP/域名（必填）
  -p, --port <num>          目标端口（必填）
  -P, --protocol <proto>    udp | http | https   (默认 udp)
  -r, --rate <num>          每线程发送速率（包/请求 每秒） (默认 ${DEFAULTS.rate})
  -t, --time <seconds>      持续时间（秒） (默认 ${DEFAULTS.time})
  -C, --threads <num>       工作线程数 (默认 CPU 核心数 ${DEFAULTS.threads})
  -s, --size <bytes>        UDP 包大小 (仅 udp) (默认 ${DEFAULTS.size})
  --min-sent <num>          成功发送/请求的最低阈值
  --max-fail <num>          允许的最大失败次数
  --min-rate <num>          平均成功速率阈值（包/秒）
  --output <json|csv>       结束时的报告格式 (默认 json)
  --quiet, -q               静默模式 – 不打印任何报告，只返回退出码
  --config <file>           JSON 配置文件（CLI 参数会覆盖）
  -h, --help                查看帮助

阈值不满足 → 退出码 2（CI 自动判为失败）  
参数错误/异常 → 退出码 1  
全部达标 → 退出码 0

⚠️ 请仅在得到目标授权的情况下使用本工具，非法攻击将承担法律责任。
`;
  stdout.write(help);
}

// ---------- 主线程 ----------
if (isMainThread) {
  const cli = parseCli();
  if (cli === null) {
    printHelp();
    exit(0);
  }

  // 合并默认值
  const cfg = { ...DEFAULTS, ...cli };

  // 参数校验
  if (!cfg.ip || Number.isNaN(cfg.port) || Number.isNaN(cfg.rate) ||
      Number.isNaN(cfg.time) || Number.isNaN(cfg.threads) ||
      !['udp', 'http', 'https'].includes(cfg.protocol)) {
    console.error('参数缺失或非法，请检查后重试。');
    printHelp();
    exit(1);
  }

  // ---------- 共享内存 ----------
  const shared = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3);
  const stats = new Int32Array(shared); // 0:sent 1:failed 2:finished

  // ---------- 启动 workers ----------
  const workers = [];
  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    for (const w of workers) w.terminate();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  for (let i = 0; i < cfg.threads; i++) {
    const w = new Worker(__filename, {
      workerData: {
        ip: cfg.ip,
        port: cfg.port,
        protocol: cfg.protocol,
        rate: cfg.rate,
        time: cfg.time,
        size: cfg.size,
        shared,
      },
    });
    workers.push(w);

    w.on('error', (err) => {
      console.error(`[线程 ${w.threadId}] 异常: ${err.message}`);
      shutdown();
    });

    w.on('exit', (code) => {
      Atomics.add(stats, 2, 1);
      if (code !== 0) console.warn(`[线程 ${w.threadId}] 非正常退出 (code=${code})`);
      if (Atomics.load(stats, 2) === cfg.threads) finalize();
    });
  }

  // 自动计时结束
  const timer = setTimeout(() => shutdown(), cfg.time * 1000);

  // ---------- 结束后统一报告 ----------
  function finalize() {
    clearTimeout(timer);
    const sent = Atomics.load(stats, 0);
    const failed = Atomics.load(stats, 1);
    const avgRate = sent / cfg.time;

    const violations = [];
    let exitCode = 0;

    if (sent < cfg.minSent) {
      violations.push(`成功数 ${sent} < 最小阈值 ${cfg.minSent}`);
      exitCode = 2;
    }
    if (failed > cfg.maxFail) {
      violations.push(`失败数 ${failed} > 最大阈值 ${cfg.maxFail}`);
      exitCode = 2;
    }
    if (avgRate < cfg.minRate) {
      violations.push(`平均速率 ${avgRate.toFixed(2)} < 最小阈值 ${cfg.minRate}`);
      exitCode = 2;
    }

    const report = {
      target: { ip: cfg.ip, port: cfg.port, protocol: cfg.protocol },
      config: {
        threads: cfg.threads,
        ratePerThread: cfg.rate,
        totalTargetRate: cfg.rate * cfg.threads,
        durationSec: cfg.time,
        packetSize: cfg.protocol === 'udp' ? cfg.size : undefined,
      },
      result: {
        sent,
        failed,
        avgRate: Number(avgRate.toFixed(2)),
        success: exitCode === 0,
        violations,
      },
      timestamp: new Date().toISOString(),
    };

    // 仅在非 quiet 时打印（人类阅读）
    if (!cfg.quiet) {
      if (cfg.output === 'csv') {
        const header = ['ip','port','protocol','threads','ratePerThread','totalTargetRate','durationSec','packetSize','sent','failed','avgRate','success'];
        const data   = [cfg.ip,cfg.port,cfg.protocol,cfg.threads,cfg.rate,cfg.rate*cfg.threads,cfg.time,cfg.protocol==='udp'?cfg.size:'',sent,failed,avgRate.toFixed(2),report.result.success];
        stdout.write(header.join(',') + '\n' + data.join(',') + '\n');
      } else {
        stdout.write(JSON.stringify(report, null, 2) + '\n');
      }
      if (exitCode === 0) console.log('\n✅ 任务成功 ✅');
      else console.error('\n❌ 任务失败 ❌');
    }

    exit(exitCode);
  }
}

// ---------- 工作线程 ----------
else {
  const { ip, port, protocol, rate, time, size, shared } = workerData;
  const stats = new Int32Array(shared);
  const INTERVAL_MS = 10;
  const tokensPerInterval = (rate * INTERVAL_MS) / 1000;
  let tokenBucket = 0;
  const start = Date.now();

  // ----------------- UDP -----------------
  if (protocol === 'udp') {
    const dgram = require('dgram');
    const socket = dgram.createSocket('udp4');
    const payload = crypto.randomBytes(size);

    const timer = setInterval(() => {
      tokenBucket += tokensPerInterval;
      while (tokenBucket >= 1) {
        tokenBucket -= 1;
        const buf = Buffer.from(payload);
        socket.send(buf, port, ip, (err) => {
          if (err) Atomics.add(stats, 1, 1);
          else Atomics.add(stats, 0, 1);
        });
      }
      if (Date.now() - start >= time * 1000) {
        clearInterval(timer);
        socket.close();
      }
    }, INTERVAL_MS);

    socket.on('error', (err) => {
      console.error(`[线程 ${threadId}] UDP socket 错误: ${err.message}`);
      clearInterval(timer);
      socket.close();
    });
  }
  // ----------------- HTTP / HTTPS -----------------
  else {
    const http = require('http');
    const https = require('https');
    const agentOpts = { keepAlive: true, maxSockets: Infinity };
    const agent = protocol === 'https' ? new https.Agent(agentOpts) : new http.Agent(agentOpts);
    const requestOpts = {
      hostname: ip,
      port,
      method: 'GET',
      path: '/',
      agent,
      timeout: 5000,
    };
    const lib = protocol === 'https' ? https : http;

    const timer = setInterval(() => {
      tokenBucket += tokensPerInterval;
      while (tokenBucket >= 1) {
        tokenBucket -= 1;
        const req = lib.request(requestOpts, (res) => {
          Atomics.add(stats, 0, 1);
          res.resume(); // 快速消费 body
        });
        req.on('error', () => Atomics.add(stats, 1, 1));
        req.on('timeout', () => {
          req.destroy();
          Atomics.add(stats, 1, 1);
        });
        req.end();
      }
      if (Date.now() - start >= time * 1000) {
        clearInterval(timer);
        agent.destroy();
      }
    }, INTERVAL_MS);
  }

  // 捕获未捕获异常，防止线程挂死
  process.on('uncaughtException', (e) => {
    console.error(`[线程 ${threadId}] 未捕获异常: ${e.stack}`);
    exit(1);
  });
}
