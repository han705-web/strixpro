"""
StrixPro CLI - 命令行入口
"""
import os
import sys
import json
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import click
from core.config import StrixProConfig
from core.fingerprint import manager as fp_manager
from core.waf_bypass import engine as waf_engine, AttackType
from core.js_analyzer import JSBundleAnalyzer
from core.scanner import Scanner
from core.report import ReportGenerator
from core.plugin_system import PluginManager


@click.group()
@click.option("--config", "-c", help="配置文件路径", default="")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.pass_context
def cli(ctx, config, verbose):
    """StrixPro - AI驱动的自动化安全测试平台

    一个完整的Web安全测试生态，支持指纹管理、WAF绕过、JS分析、报告生成等功能。
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = StrixProConfig.load(config)

    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if verbose:
        click.echo(click.style("""
  ================================
     StrixPro  v1.0.0
     AI驱动的安全测试平台
  ================================
        """, fg="cyan"))


@cli.command()
@click.pass_context
def info(ctx):
    """显示系统信息"""
    config = ctx.obj["config"]
    click.echo(click.style("\n[ StrixPro 系统信息 ]", fg="cyan", bold=True))
    click.echo("  版本: 1.0.0")
    click.echo("  配置: %s" % config.output_dir)
    click.echo("  专业版: %s" % ("已激活" if config.is_pro else "未激活"))

    click.echo(click.style("\n[ 可用浏览器指纹 ]", fg="cyan", bold=True))
    for fp in fp_manager.list_profiles():
        click.echo("  + %s (%s)" % (fp['name'], fp['id']))

    click.echo(click.style("\n[ 支持的攻击类型 ]", fg="cyan", bold=True))
    for at in AttackType:
        click.echo("  + %s" % at.value)

    click.echo(click.style("\n[ 插件系统 ]", fg="cyan", bold=True))
    pm = PluginManager(config.plugins_dir)
    available = pm.discover()
    click.echo("  发现 %d 个插件" % len(available))


@cli.group()
def fingerprint():
    """浏览器指纹管理"""
    pass


@fingerprint.command()
def list():
    """列出所有可用指纹"""
    click.echo(click.style("\n[ 可用浏览器指纹 ]", fg="cyan", bold=True))
    for fp in fp_manager.list_profiles():
        click.echo("  + %s (%s)" % (fp['name'], fp['id']))
    click.echo("\n总计: %d 个指纹" % len(fp_manager.list_profiles()))


@fingerprint.command()
@click.argument("profile_id", default="chrome_131")
@click.pass_context
def show(ctx, profile_id):
    """显示指纹详情"""
    fp = fp_manager.get(profile_id)
    click.echo(click.style("\n[ 指纹详情: %s ]" % fp.name, fg="cyan", bold=True))
    click.echo("  User-Agent: %s" % fp.ua)
    click.echo("  JA3: %s..." % fp.tls.get('ja3', 'N/A')[:60])
    click.echo("  Accept-Language: %s" % fp.accept_language)
    if fp.sec_ch_ua:
        click.echo("  Sec-Ch-Ua: %s" % fp.sec_ch_ua)


@cli.group()
def waf():
    """WAF绕过Payload生成"""
    pass


@waf.command()
@click.option("--type", "-t", "attack_type", default="xss", help="攻击类型 (xss/sqli/ssrf/cmdi/ssti/lfi)")
@click.option("--count", "-n", default=10, help="生成数量")
@click.option("--output", "-o", default="", help="输出文件")
def generate(attack_type, count, output):
    """生成WAF绕过payload"""
    try:
        at = AttackType(attack_type)
    except ValueError:
        click.echo(click.style("[X] 无效的攻击类型: %s" % attack_type, fg="red"))
        click.echo("   支持的类型: %s" % ", ".join(at.value for at in AttackType))
        return

    click.echo(click.style("\n[ 生成 %s 绕过Payload (%d个) ]" % (attack_type.upper(), count), fg="cyan", bold=True))
    payloads = waf_engine.generate(at, count=count)

    for p in payloads:
        click.echo("\n  [%s] 编码: %s" % (p['id'], p['encoding']))
        click.echo("      原始: %s" % p['original'][:60])
        click.echo("      编码: %s" % p['encoded'][:80])

    if output:
        with open(output, "w") as f:
            for p in payloads:
                f.write(p["encoded"] + "\n")
        click.echo(click.style("[V] 已保存到 %s" % output, fg="green"))


@cli.group()
def scan():
    """扫描目标"""
    pass


@scan.command()
@click.argument("url")
@click.option("--check-headers", is_flag=True, help="检查安全头部")
@click.option("--check-cors", is_flag=True, help="检查CORS配置")
@click.option("--output", "-o", default="", help="输出文件路径")
@click.pass_context
def quick(ctx, url, check_headers, check_cors, output):
    """快速扫描目标"""
    click.echo(click.style("\n[ 开始扫描: %s ]" % url, fg="cyan", bold=True))

    scanner = Scanner(ctx.obj["config"])
    reporter = ReportGenerator()

    data = {"target": url, "vulnerabilities": [], "security_headers": {}, "summary": {"total_findings": 0}}

    if check_headers:
        click.echo("  [>] 检查安全头部...")
        header_result = scanner.check_security_headers(url)
        data["security_headers"] = header_result.get("headers", {})
        missing = sum(1 for v in data["security_headers"].values() if not v.get("present"))
        click.echo("    缺失 %d 个安全头部" % missing)

    if check_cors:
        click.echo("  [>] 检查CORS配置...")
        cors_result = scanner.check_cors(url)
        if cors_result.get("findings"):
            click.echo(click.style("    [!!] 发现 %d 个CORS问题" % len(cors_result['findings']), fg="yellow"))
            data["vulnerabilities"].extend(cors_result["findings"])
        else:
            click.echo("    [OK] 未发现CORS问题")

    if output:
        path = reporter.save(data, fmt="markdown", filename=output)
        click.echo(click.style("[V] 报告已保存: %s" % path, fg="green"))
    else:
        report = reporter.generate(data)
        click.echo("\n" + report)


@cli.group()
def js():
    """JavaScript Bundle分析"""
    pass


@js.command()
@click.argument("target")
@click.option("--output", "-o", default="", help="输出文件")
@click.option("--base-url", default="", help="基础URL（用于补全相对路径）")
def analyze(target, output, base_url):
    """分析JS文件或URL"""
    click.echo(click.style("\n[ 分析JS: %s ]" % target, fg="cyan", bold=True))

    analyzer = JSBundleAnalyzer()

    if os.path.isdir(target):
        results = analyzer.scan_directory(target)
        click.echo("  扫描了 %d 个文件" % len(results))
    elif os.path.isfile(target):
        result = analyzer.analyze_file(target)
        click.echo("  文件大小: %d 字节" % result.get('size', 0))
        summary = result.get("summary", {})
        click.echo("  发现: %d 项" % summary.get('total_findings', 0))
        for cat, matches in result.get("findings", {}).items():
            click.echo("    + %s: %d 个" % (cat, len(matches)))

        if result.get("api_endpoints"):
            click.echo(click.style("\n  [API端点 (%d)]:" % len(result['api_endpoints']), fg="green"))
            for ep in result["api_endpoints"][:20]:
                click.echo("    + %s" % ep)

        if result.get("sensitive_data"):
            click.echo(click.style("\n  [敏感信息 (%d)]:" % len(result['sensitive_data']), fg="yellow"))
            for item in result["sensitive_data"][:10]:
                click.echo("    + %s" % item.get('value', '')[:100])
    else:
        import requests as req
        try:
            resp = req.get(target, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
            result = analyzer.analyze_bundle(resp.text, base_url or target)
            click.echo("  内容大小: %d 字节" % len(resp.text))
            summary = result.get("summary", {})
            click.echo("  发现: %d 项" % summary.get('total_findings', 0))
            if result.get("api_endpoints"):
                click.echo(click.style("\n  [API端点]:" % (), fg="green"))
                for ep in result["api_endpoints"][:30]:
                    click.echo("    + %s" % ep)
        except Exception as e:
            click.echo(click.style("[X] 错误: %s" % e, fg="red"))
            return

    if output:
        result_data = result if 'result' in dir() else results
        with open(output, "w") as f:
            json.dump(result_data, f, ensure_ascii=False, indent=2)
        click.echo(click.style("[V] 已保存到 %s" % output, fg="green"))


@cli.command()
@click.argument("url")
@click.option("--output", "-o", default="", help="输出文件")
@click.option("--format", "-f", "fmt", default="markdown", help="输出格式 (markdown/html/json)")
@click.pass_context
def audit(ctx, url, output, fmt):
    """全面审计目标"""
    click.echo(click.style("\n[ 全面安全审计: %s ]" % url, fg="cyan", bold=True))

    scanner = Scanner(ctx.obj["config"])
    reporter = ReportGenerator(output_dir="./output")

    data = {
        "target": url,
        "summary": {"total_findings": 0, "severity_counts": {}},
        "vulnerabilities": [],
        "security_headers": {},
        "api_endpoints": [],
    }

    # Step 1: Security headers
    click.echo("  [1/4] 检查安全头部...")
    header_result = scanner.check_security_headers(url)
    data["security_headers"] = header_result.get("headers", {})

    # Step 2: CORS
    click.echo("  [2/4] 检查CORS配置...")
    cors_result = scanner.check_cors(url)
    if cors_result.get("findings"):
        for f in cors_result["findings"]:
            data["vulnerabilities"].append({
                "title": "CORS配置不当",
                "type": "cors",
                "target": url,
                "severity": f.get("severity", "high"),
                "description": "Origin反射: %s" % f.get('origin'),
                "evidence": json.dumps(f, ensure_ascii=False),
            })

    # Step 3: Try to fetch and analyze JS
    click.echo("  [3/4] 尝试获取JS进行分析...")
    try:
        resp = scanner.get(url)
        if resp:
            analyzer = JSBundleAnalyzer()
            js_result = analyzer.analyze_bundle(resp.text, url)
            data["api_endpoints"] = js_result.get("api_endpoints", [])
            if js_result.get("sensitive_data"):
                for sd in js_result["sensitive_data"]:
                    data["vulnerabilities"].append({
                        "title": "敏感信息泄露",
                        "type": "info_disclosure",
                        "target": url,
                        "severity": "high",
                        "evidence": sd.get("value", ""),
                    })
    except Exception as e:
        click.echo("  [W] JS分析失败: %s" % e)

    # Step 4: Summary
    vuln_count = len(data["vulnerabilities"])
    data["summary"]["total_findings"] = vuln_count
    for v in data["vulnerabilities"]:
        sev = v.get("severity", "info")
        data["summary"]["severity_counts"][sev] = data["summary"]["severity_counts"].get(sev, 0) + 1

    click.echo("  [4/4] 完成! 发现 %d 个问题" % vuln_count)

    # Generate report
    if output:
        path = reporter.save(data, fmt=fmt, filename=output)
        click.echo(click.style("[V] 审计报告已保存: %s" % path, fg="green"))
    else:
        report = reporter.generate(data, fmt=fmt)
        click.echo("\n" + report)


@cli.command()
@click.option("--port", "-p", default=8765, help="Web服务端口")
@click.pass_context
def serve(ctx, port):
    """启动Web服务"""
    from web.app import start_server
    click.echo(click.style("\n[ 启动StrixPro Web服务 (端口: %d) ]" % port, fg="cyan", bold=True))
    click.echo("  访问 http://localhost:%d" % port)
    click.echo("  API文档 http://localhost:%d/docs" % port)
    start_server(port=port)


@cli.command()
@click.option("--output-dir", default="./output", help="输出目录")
@click.pass_context
def init(ctx, output_dir):
    """初始化工作目录"""
    dirs = [output_dir, "plugins", "config"]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
        click.echo("  [+] 创建: %s/" % d)

    # Generate default config
    config = ctx.obj["config"]
    config.output_dir = output_dir
    config.save("config/strixpro.json")
    click.echo("  [*] 配置文件: config/strixpro.json")

    click.echo(click.style("\n[V] StrixPro 初始化完成!", fg="green"))
    click.echo("  运行 'strixpro --help' 查看可用命令")


if __name__ == "__main__":
    cli()
