

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
  rate: 1000,          // 每线程速率（如果未给 totalRate）
  time: 10,
  threads: os.cpus().length, // 默认使用机器最大核心数
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

  // JSON 配置文件（可选）
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
      case '-P':
      case '--protocol':
        args.protocol = argv[++i].toLowerCase();
        break;
      case '-r':
      case '--rate':
        args.rate = Number(argv[++i]); // 每线程速率
        break;
      case '-R':
      case '--total-rate':
        args.totalRate = Number(argv[++i]); // 全局速率
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
    totalRate: env.FLOOD_TOTAL_RATE && Number(env.FLOOD_TOTAL_RATE),
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
cc-mod.js – 自动最大化线程数、支持全局速率的压测工具

  node cc-mod.js [options]

选项:
  -i, --ip <host>           目标 IP/域名（必填，**不要带 http/https 前缀**）
  -p, --port <num>          目标端口（必填）
  -P, --protocol <proto>    udp | http | https          (默认 udp)
  -r, --rate <num>          每线程发送速率（包/请求 每秒）   (默认 ${DEFAULTS.rate})
  -R, --total-rate <num>    **全局速率**（所有线程累计的速率），脚本会自动均分到每个线程
  -t, --time <seconds>      持续时间（秒）                (默认 ${DEFAULTS.time})
  -C, --threads <num>       工作线程数（默认使用机器最大核心数 ${DEFAULTS.threads})
  -s, --size <bytes>        UDP 包大小（仅 udp）           (默认 ${DEFAULTS.size})
  --min-sent <num>          成功发送/请求的最小阈值
  --max-fail <num>          允许的最大失败次数
  --min-rate <num>          平均成功速率阈值（包/秒）
  --output <json|csv>       结束时的报告格式 (默认 json)
  -q, --quiet               静默模式 – 只返回退出码，不输出报告
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

  // 合并默认值，threads 默认使用机器最大核心数
  const cfg = {
    ...DEFAULTS,
    threads: os.cpus().length, // <-- 自动最大线程数
    ...cli,
  };

  // 参数合法性检查
  if (!cfg.ip) {
    console.error('错误：请使用 -i 指定目标主机（不要带 http/https 前缀）。');
    exit(1);
  }
  if (Number.isNaN(cfg.port) || cfg.port <= 0) {
    console.error('错误：-p 必须是有效的端口号。');
    exit(1);
  }
  if (!['udp', 'http', 'https'].includes(cfg.protocol)) {
    console.error('错误：-P 只能是 udp、http、https 其中之一。');
    exit(1);
  }
  if (Number.isNaN(cfg.time) || cfg.time <= 0) {
    console.error('错误：-t 必须是正数（秒）。');
    exit(1);
  }

  // ---------- 计算每线程实际速率 ----------
  // 1️⃣ 如果用户提供了全局速率，则自动均分
  if (typeof cfg.totalRate === 'number' && !Number.isNaN(cfg.totalRate)) {
    cfg.rate = Math.ceil(cfg.totalRate / cfg.threads);
    if (!cfg.quiet) console.log(`[信息] 全局速率 ${cfg.totalRate} 已均分到每线程 ${cfg.rate}（共 ${cfg.threads} 条线程）`);
  } else {
    // 2️⃣ 没有全局速率时使用每线程速率（若未提供则使用默认值）
    if (typeof cfg.rate !== 'number' || Number.isNaN(cfg.rate)) cfg.rate = DEFAULTS.rate;
  }

  // ---------- 系统资源提示 ----------
  function checkSystemLimits(threadCount) {
    const { execSync } = require('child_process');
    try {
      const nofile = Number(execSync('ulimit -n', { encoding: 'utf8' }).trim());
      if (nofile < threadCount * 2) {
        console.warn(`[警告] 当前进程的 open file 限制 (${nofile}) 可能不足以支撑 ${threadCount} 个 worker。`);
        console.warn('建议执行：ulimit -n 65535   或者在 /etc/security/limits.conf 中提升软/硬限制。');
      }
    } catch (_) {
      // Windows 或不支持 ulimit 的环境直接忽略
    }
  }
  checkSystemLimits(cfg.threads);

  // ---------- 共享内存 ----------
  const shared = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3);
  const stats = new Int32Array(shared); // 0:sent, 1:failed, 2:finished workers

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

  if (!cfg.quiet) {
    console.log(`启动 ${cfg.threads} 个工作线程 → ${cfg.protocol.toUpperCase()} ${cfg.ip}:${cfg.port}`);
    console.log(`每线程速率 ${cfg.rate} ${cfg.protocol === 'udp' ? '包' : '请求'}/秒，持续 ${cfg.time}s`);
  }

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

    // 只在非 quiet 模式下打印结构化报告
    if (!cfg.quiet) {
      if (cfg.output === 'csv') {
        const header = [
          'ip', 'port', 'protocol', 'threads', 'ratePerThread',
          'totalTargetRate', 'durationSec', 'packetSize',
          'sent', 'failed', 'avgRate', 'success',
        ];
        const data = [
          cfg.ip, cfg.port, cfg.protocol, cfg.threads, cfg.rate,
          cfg.rate * cfg.threads, cfg.time, cfg.protocol === 'udp' ? cfg.size : '',
          sent, failed, avgRate.toFixed(2), report.result.success,
        ];
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

/* ------------------------------------------------------------------
   工作线程：UDP / HTTP / HTTPS 实际发送
   ------------------------------------------------------------------ */
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
      path: '/',          // 若需要自定义路径，可在配置文件中覆盖
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
          res.resume(); // 快速消费 body，防止内存堆积
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
