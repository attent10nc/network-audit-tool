#!/usr/bin/env python3
"""
Advanced Network Audit & Pentest Tool
Automates Nmap scanning, parsing, vulnerability assessment, and reporting.
Ready for GitHub deployment.
"""

import nmap
import argparse
import logging
import time
import json
import sys
import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.prompt import Prompt, Confirm

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)]
)
logger = logging.getLogger("recon_scanner")

CURRENT_LANG = "en"

TRANSLATIONS = {
    "en": {
        "banner_sub": "Network Audit & Pentest Tool",
        "lang_prompt": "Select Language / Выберите язык",
        "target_prompt": "Enter IP address or domain (or 'q' to quit)",
        "quit_msg": "Exiting. Stay safe!",
        "current_target": "► Current target: {} ◄",
        "menu_fast": "Fast scan (top 100 ports)",
        "menu_full": "Full scan (all 65535 ports)",
        "menu_aggr": "Aggressive (OS, services, traceroute)",
        "menu_vuln": "Vulnerability search (CVEs)",
        "menu_pent": "Active pentest (brute-force, exploits)",
        "menu_dos": "DoS resistance check",
        "menu_back": "Back to target selection",
        "action_prompt": "Select an action",
        "save_prompt": "Save report to files?",
        "file_prompt": "Enter base filename",
        "press_enter": "Press Enter to continue with this target...",
        "init_nmap": "Initializing Nmap for target: {} (Mode: {})",
        "nmap_error": "Nmap not found! Ensure it is installed and in PATH.",
        "scan_start": "Starting scan with args: {}",
        "scan_err": "Scan error: {}",
        "done_time": "Action completed in {:.2f} seconds.",
        "host_down": "Target {} is down or blocking pings.",
        "gen_info": "General Information",
        "status": "Status",
        "os_guess": "OS Guess",
        "unknown": "Unknown",
        "up": "Up",
        "table_title": "Scan Results",
        "col_port": "Port",
        "col_state": "State",
        "col_service": "Service",
        "col_version": "Version",
        "col_http": "HTTP Info",
        "col_scripts": "Active Scripts",
        "vuln_level": "NETWORK VULNERABILITY LEVEL: [{0}]{1}%[/{0}]",
        "vectors_title": "--- Possible Attack Vectors ---",
        "recom_title": "--- Recommendations ---",
        "panel_title_safe": "Security Analysis",
        "panel_title_warn": "Attack Vectors & Recommendations",
        "saved_files": "Reports saved as {}.json and {}.txt",
        "rec_close": "Port {}: Close port. Use secure alternatives.",
        "rec_vpn": "Port {}: Restrict IP access, use VPN or SSH keys.",
        "rec_smb": "Port {}: CRITICAL. Close external access immediately (Windows SMB).",
        "rec_web": "Port {}: Keep web server and CMS updated.",
        "rec_db": "Port {}: Hide database behind a firewall.",
        "rec_dns": "Port {}: Close public DNS resolver.",
        "rec_patch": "Port {}: Urgent! Install patch for {}.",
        "rec_pwd": "Port {}: CHANGE PASSWORD IMMEDIATELY! Brute-force succeeded ({}).",
        "rec_ftp": "Port {}: Disable anonymous FTP login.",
        "rec_dos": "Port {}: Service vulnerable to DoS ({}).",
        "rec_safe": "EXCELLENT: No open ports found.",
        "vec_sniff": "Port {} ({}): Traffic interception (sniffing) possible.",
        "vec_brute": "Port {} ({}): Brute-force attack possible.",
        "vec_smb": "Port {} ({}): Ransomware infection possible via SMB exploit.",
        "vec_web": "Port {} ({}): Web exploit execution possible.",
        "vec_db": "Port {} ({}): Data leak / SQL injection possible.",
        "vec_dns": "Port {} ({}): Can be used for DDoS amplification.",
        "vec_cve": "Port {} ({}): Exploit vulnerability - CONFIRMED.",
        "vec_pwd": "Port {} ({}): Brute-force - SUCCESS. Weak credentials used.",
        "vec_ftp": "Port {} (FTP): Anonymous access allowed.",
        "vec_dos": "Port {} ({}): DoS vulnerability - CONFIRMED.",
        "vec_safe": "No direct external attack vectors found. Network is closed.",
        "txt_report_title": "SCAN REPORT",
        "txt_ports": "FOUND PORTS & SERVICES:",
        "txt_vectors": "POSSIBLE ATTACK VECTORS:",
        "txt_recom": "SECURITY RECOMMENDATIONS:",
    },
    "ru": {
        "banner_sub": "Утилита для аудита сетей и пентеста",
        "lang_prompt": "Выберите язык / Select Language",
        "target_prompt": "Введите IP-адрес или домен (или 'q' для выхода)",
        "quit_msg": "Завершение работы. Безопасного интернета!",
        "current_target": "► Текущая цель: {} ◄",
        "menu_fast": "Быстрое сканирование (топ 100 портов)",
        "menu_full": "Полное сканирование (все 65535 портов)",
        "menu_aggr": "Агрессивное (ОС, сервисы, трассировка)",
        "menu_vuln": "Поиск уязвимостей (базы CVE)",
        "menu_pent": "Активный пентест (брутфорс, эксплойты)",
        "menu_dos": "Проверка устойчивости к DoS",
        "menu_back": "Вернуться к выбору цели",
        "action_prompt": "Выберите действие",
        "save_prompt": "Сохранить отчет в файлы?",
        "file_prompt": "Введите имя файла",
        "press_enter": "Нажмите Enter для продолжения работы с целью...",
        "init_nmap": "Инициализация Nmap для: {} (Режим: {})",
        "nmap_error": "Nmap не найден! Убедитесь, что он установлен.",
        "scan_start": "Запуск сканирования (аргументы: {})",
        "scan_err": "Ошибка сканирования: {}",
        "done_time": "Действие завершено за {:.2f} сек.",
        "host_down": "Цель {} недоступна (Host is down).",
        "gen_info": "Общая информация",
        "status": "Статус",
        "os_guess": "Предполагаемая ОС",
        "unknown": "Неизвестно",
        "up": "Узел активен",
        "table_title": "Результаты сканирования",
        "col_port": "Порт",
        "col_state": "Статус",
        "col_service": "Сервис",
        "col_version": "Версия",
        "col_http": "HTTP Инфо",
        "col_scripts": "Активные проверки",
        "vuln_level": "УРОВЕНЬ УЯЗВИМОСТИ СЕТИ: [{0}]{1}%[/{0}]",
        "vectors_title": "--- Возможные векторы атак ---",
        "recom_title": "--- Рекомендации ---",
        "panel_title_safe": "Анализ безопасности",
        "panel_title_warn": "Векторы атак и Рекомендации",
        "saved_files": "Отчеты сохранены как {}.json и {}.txt",
        "rec_close": "Порт {}: Закройте порт. Используйте шифрованные аналоги.",
        "rec_vpn": "Порт {}: Ограничьте доступ по IP, используйте VPN/ключи.",
        "rec_smb": "Порт {}: Срочно закройте доступ извне (SMB).",
        "rec_web": "Порт {}: Своевременно обновляйте веб-сервер и CMS.",
        "rec_db": "Порт {}: Спрячьте базу данных за файрволом.",
        "rec_dns": "Порт {}: Закройте публичный DNS-резолвер.",
        "rec_patch": "Порт {}: Срочно установите патч для уязвимости {}.",
        "rec_pwd": "Порт {}: СМЕНИТЕ ПАРОЛЬ НЕМЕДЛЕННО! Успешный брутфорс ({}).",
        "rec_ftp": "Порт {}: Запретите анонимный вход на FTP.",
        "rec_dos": "Порт {}: Сервис уязвим к отказу в обслуживании ({}).",
        "rec_safe": "ОТЛИЧНО: Открытых портов не обнаружено.",
        "vec_sniff": "Порт {} ({}): Возможен перехват трафика (сниффинг).",
        "vec_brute": "Порт {} ({}): Возможен брутфорс (перебор паролей).",
        "vec_smb": "Порт {} ({}): Возможно заражение Ransomware.",
        "vec_web": "Порт {} ({}): Возможно использование веб-эксплойтов.",
        "vec_db": "Порт {} ({}): Утечка данных / SQL-инъекции возможны.",
        "vec_dns": "Порт {} ({}): Использование для DDoS атак (усиление).",
        "vec_cve": "Порт {} ({}): Взлом через эксплойт - ПОДТВЕРЖДЕНО.",
        "vec_pwd": "Порт {} ({}): Брутфорс - УСПЕШЕН. Используется слабый пароль.",
        "vec_ftp": "Порт {} (FTP): Доступ без пароля открыт.",
        "vec_dos": "Порт {} ({}): Опасность DoS - ПОДТВЕРЖДЕНО.",
        "vec_safe": "Прямые векторы атак отсутствуют. Сеть закрыта.",
        "txt_report_title": "ОТЧЕТ СКАНИРОВАНИЯ",
        "txt_ports": "НАЙДЕННЫЕ ПОРТЫ И СЕРВИСЫ:",
        "txt_vectors": "ВОЗМОЖНЫЕ ВЕКТОРЫ АТАК:",
        "txt_recom": "РЕКОМЕНДАЦИИ ПО ЗАЩИТЕ:",
    }
}


def t(key, *args):
    """Localization helper."""
    text = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["en"]).get(key, key)
    if args:
        return text.format(*args)
    return text


BANNER = r"""
[bold red]    ___  ___________ _____ _   _ _____ _____ _____ _   _ [/bold red]
[bold yellow]   / _ \|_   _|_   _|  ___| \ | |_   _|_   _|  _  | \ | |[/bold yellow]
[bold green]  / /_\ \ | |   | | | |__ |  \| | | |   | | | | | |  \| |[/bold green]
[bold cyan]  |  _  | | |   | | |  __|| . ` | | |   | | | | | | . ` |[/bold cyan]
[bold blue]  | | | | | |   | | | |___| |\  | | |  _| |_\ \_/ / |\  |[/bold blue]
[bold magenta]  \_| |_/ \_/   \_/ \____/\_| \_/ \_/  \___/ \___/\_| \_/[/bold magenta]
[bold white]                  {}             [/bold white]
"""


def analyze_http_services(target, port, is_https=False):
    protocol = "https" if is_https or port == 443 else "http"
    url = f"{protocol}://{target}:{port}"
    http_info = {"url": url, "server": t("unknown"), "x_powered_by": t("unknown"), "status_code": None}

    try:
        response = requests.get(url, timeout=5, verify=False)
        http_info["status_code"] = response.status_code
        http_info["server"] = response.headers.get("Server", t("unknown"))
        http_info["x_powered_by"] = response.headers.get("X-Powered-By", t("unknown"))
    except requests.exceptions.RequestException:
        http_info["server"] = "Connection Error"

    return http_info


def scan_target(target, mode="fast"):
    logger.info(t("init_nmap", target, mode))
    try:
        nmap_paths = (
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe',
            'nmap',
            '/usr/bin/nmap',
            '/usr/local/bin/nmap'
        )
        scanner = nmap.PortScanner(nmap_search_path=nmap_paths)
    except nmap.PortScannerError:
        logger.error(t("nmap_error"))
        sys.exit(1)

    # Performance tuned arguments to prevent hanging
    base_args = "-T4 --min-rate 1000"

    if mode == "fast":
        args = f"{base_args} -F -sV"
    elif mode == "full":
        args = f"{base_args} -p- -sV"
    elif mode == "aggressive":
        args = f"{base_args} -p- -A"
    elif mode == "vuln":
        args = f"{base_args} -sV --script vuln,vulners --host-timeout 30m"
    elif mode == "pentest":
        args = f"{base_args} --top-ports 1000 -sV --script vuln,vulners,auth,brute --script-args unpwdb.timelimit=3m,ssh-brute.timeout=3m --host-timeout 45m"
    elif mode == "dos_check":
        args = f"{base_args} --top-ports 1000 -sV --script dos"
    else:
        args = f"{base_args} -F -sV"

    try:
        logger.info(t("scan_start", args))
        scanner.scan(hosts=target, arguments=args)
        return scanner
    except Exception as e:
        logger.error(t("scan_err", str(e)))
        sys.exit(1)


def parse_results(scanner, target_ip):
    results = {
        "target": target_ip,
        "state": "down",
        "os_matches": [],
        "ports": []
    }

    if not scanner.all_hosts():
        return results

    host = scanner.all_hosts()[0]
    results["state"] = scanner[host].state()

    if 'osmatch' in scanner[host]:
        for os in scanner[host]['osmatch']:
            results["os_matches"].append({
                "name": os['name'],
                "accuracy": os['accuracy']
            })

    if 'tcp' in scanner[host]:
        for port in sorted(scanner[host]['tcp'].keys()):
            port_data = scanner[host]['tcp'][port]
            if port_data['state'] == 'open':
                service_name = port_data['name']

                port_info = {
                    "port": port,
                    "state": port_data['state'],
                    "service": service_name,
                    "version": f"{port_data.get('product', '')} {port_data.get('version', '')}".strip(),
                    "http_info": None,
                    "scripts": port_data.get('script', {})
                }

                if service_name in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                    is_https = (service_name == 'https' or port == 443)
                    port_info["http_info"] = analyze_http_services(target_ip, port, is_https)

                results["ports"].append(port_info)

    return results


def analyze_vulnerabilities(parsed_results):
    recommendations = []
    attack_vectors = []
    vulnerability_score = 0

    for port_info in parsed_results['ports']:
        port = port_info['port']
        service = port_info['service']
        scripts = port_info.get('scripts', {})

        vulnerability_score += 5

        if port in [21, 23]:
            vulnerability_score += 20
            recommendations.append(f"[bold red]{t('rec_close', port)}[/bold red]")
            attack_vectors.append(f"[bold]{t('vec_sniff', port, service)}[/bold]")

        elif port in [22, 3389]:
            vulnerability_score += 15
            recommendations.append(f"[bold yellow]{t('rec_vpn', port)}[/bold yellow]")
            attack_vectors.append(f"[bold]{t('vec_brute', port, service)}[/bold]")

        elif port in [445, 139]:
            vulnerability_score += 30
            recommendations.append(f"[bold red]{t('rec_smb', port)}[/bold red]")
            attack_vectors.append(f"[bold]{t('vec_smb', port, service)}[/bold]")

        elif port in [80, 443, 8080]:
            vulnerability_score += 10
            recommendations.append(f"[bold yellow]{t('rec_web', port)}[/bold yellow]")
            attack_vectors.append(f"[bold]{t('vec_web', port, service)}[/bold]")

        elif port in [3306, 1433, 5432]:
            vulnerability_score += 25
            recommendations.append(f"[bold red]{t('rec_db', port)}[/bold red]")
            attack_vectors.append(f"[bold]{t('vec_db', port, service)}[/bold]")

        elif port == 53:
            vulnerability_score += 15
            recommendations.append(f"[bold red]{t('rec_dns', port)}[/bold red]")
            attack_vectors.append(f"[bold]{t('vec_dns', port, service)}[/bold]")

        if scripts:
            for script_name, script_output in scripts.items():
                output_upper = script_output.upper()

                is_vuln = (
                                      "VULNERABLE" in output_upper or "CVE" in output_upper or "EXPLOIT" in output_upper) and "NOT VULNERABLE" not in output_upper
                is_brute = ("VALID CREDENTIALS" in output_upper) or (
                            "ACCOUNTS:" in output_upper and "NO VALID ACCOUNTS FOUND" not in output_upper)

                if is_vuln:
                    vulnerability_score += 40
                    recommendations.append(f"[bold red]{t('rec_patch', port, script_name)}[/bold red]")
                    attack_vectors.append(f"[bold red]{t('vec_cve', port, script_name)}[/bold red]")

                if is_brute:
                    vulnerability_score += 50
                    recommendations.append(f"[bold red]{t('rec_pwd', port, script_name)}[/bold red]")
                    attack_vectors.append(f"[bold red]{t('vec_pwd', port, script_name)}[/bold red]")

                if "ANONYMOUS FTP LOGIN ALLOWED" in output_upper:
                    vulnerability_score += 30
                    recommendations.append(f"[bold red]{t('rec_ftp', port)}[/bold red]")
                    attack_vectors.append(f"[bold red]{t('vec_ftp', port)}[/bold red]")

                if "DOS" in output_upper and is_vuln:
                    vulnerability_score += 35
                    recommendations.append(f"[bold red]{t('rec_dos', port, script_name)}[/bold red]")
                    attack_vectors.append(f"[bold red]{t('vec_dos', port, script_name)}[/bold red]")

    if len(parsed_results['ports']) == 0:
        recommendations.append(f"[bold green]{t('rec_safe')}[/bold green]")
        attack_vectors.append(t('vec_safe'))

    vulnerability_score = min(vulnerability_score, 100)
    return recommendations, attack_vectors, vulnerability_score


def generate_report(results, output_file=None):
    if results["state"] != "open" and results["state"] != "up":
        console.print(Panel(f"[bold red]{t('host_down', results['target'])}[/bold red]"))
        return

    os_info = t("unknown")
    if results["os_matches"]:
        os_info = f"{results['os_matches'][0]['name']} ({results['os_matches'][0]['accuracy']}%)"

    info_text = f"[bold green]IP/Domain:[/bold green] {results['target']}\n"
    info_text += f"[bold green]{t('status')}:[/bold green] {t('up')}\n"
    info_text += f"[bold green]{t('os_guess')}:[/bold green] {os_info}"

    console.print(Panel(info_text, title=f"[bold blue]{t('gen_info')}[/bold blue]", expand=False))

    table = Table(title=t("table_title"), show_header=True, header_style="bold magenta")
    table.add_column(t("col_port"), style="cyan", justify="right")
    table.add_column(t("col_state"), style="green")
    table.add_column(t("col_service"), style="yellow")
    table.add_column(t("col_version"), style="white")
    table.add_column(t("col_http"), style="blue")
    table.add_column(t("col_scripts"), style="red")

    for p in results["ports"]:
        http_str = ""
        if p["http_info"]:
            http_str = f"Server: {p['http_info']['server']}\nX-Powered-By: {p['http_info']['x_powered_by']}"

        script_output = []
        for script_name, script_result in p["scripts"].items():
            clean_result = str(script_result).strip().replace('\n', ' ')
            if len(clean_result) > 60:
                clean_result = clean_result[:57] + "..."
            script_output.append(f"[bold]{script_name}[/bold]: {clean_result}")
        scripts_str = "\n".join(script_output) if script_output else "-"

        table.add_row(
            str(p["port"]),
            p["state"],
            p["service"],
            p["version"] if p["version"] else "-",
            http_str if http_str else "-",
            scripts_str
        )

    console.print(table)

    recommendations, attack_vectors, vuln_score = analyze_vulnerabilities(results)

    score_color = "green"
    if vuln_score >= 20: score_color = "yellow"
    if vuln_score >= 50: score_color = "red"

    score_text = f"\n[bold]{t('vuln_level', score_color, vuln_score)}[/bold]\n"
    recom_title = f"[bold red]{t('panel_title_warn')}[/bold red]" if vuln_score > 0 else f"[bold green]{t('panel_title_safe')}[/bold green]"

    full_analysis_text = score_text
    full_analysis_text += f"\n[bold cyan]{t('vectors_title')}[/bold cyan]\n"
    full_analysis_text += "\n".join([f"• {vec}" for vec in attack_vectors]) + "\n\n"
    full_analysis_text += f"[bold cyan]{t('recom_title')}[/bold cyan]\n"
    full_analysis_text += "\n".join([f"• {rec}" for rec in recommendations])

    console.print(Panel(full_analysis_text, title=recom_title, expand=False))

    if output_file:
        json_file = f"{output_file}.json"
        txt_file = f"{output_file}.txt"

        with open(json_file, 'w', encoding='utf-8') as f:
            results['analysis'] = {
                'vulnerability_score_percent': vuln_score,
                'attack_vectors': attack_vectors,
                'recommendations': recommendations
            }
            json.dump(results, f, indent=4, ensure_ascii=False)

        with open(txt_file, 'w', encoding='utf-8') as f:
            def clean_rich(text):
                import re
                return re.sub(r'\[/?(?:bold|cyan|yellow|red|green|white|magenta|blue|/)\]', '', text)

            f.write(f"{t('txt_report_title')}: {results['target']}\n")
            f.write("=" * 80 + "\n")
            clean_score_text = clean_rich(t('vuln_level', '', vuln_score))
            f.write(f"{clean_score_text}\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"{t('txt_ports')}\n")
            f.write("-" * 80 + "\n")
            for p in results["ports"]:
                f.write(f"Port: {p['port']} | Service: {p['service']} | Version: {p['version']}\n")
                if p["http_info"]:
                    f.write(f"  -> HTTP Server: {p['http_info']['server']}\n")
                if p["scripts"]:
                    f.write("  -> Scripts:\n")
                    for s_name, s_res in p["scripts"].items():
                        f.write(f"     [{s_name}]:\n       {s_res.strip().replace(chr(10), chr(10) + '       ')}\n")
                f.write("-" * 80 + "\n")

            f.write(f"\n{t('txt_vectors')}\n")
            for vec in attack_vectors:
                f.write(f"- {clean_rich(vec)}\n")

            f.write(f"\n{t('txt_recom')}\n")
            for rec in recommendations:
                f.write(f"- {clean_rich(rec)}\n")

        logger.info(t("saved_files", output_file, output_file))


def interactive_mode():
    global CURRENT_LANG
    console.print(BANNER.format("Network Audit & Pentest Tool"))

    lang_choice = Prompt.ask("[bold cyan]Select Language / Выберите язык[/bold cyan]\n[1] English\n[2] Русский\n>",
                             choices=["1", "2"], default="1")
    CURRENT_LANG = "en" if lang_choice == "1" else "ru"

    console.clear()
    console.print(BANNER.format(t("banner_sub")))

    while True:
        target = Prompt.ask(f"\n[bold white]{t('target_prompt')}[/bold white]")

        if target.lower() in ['q', 'й', 'exit', 'quit']:
            console.print(f"[bold green]{t('quit_msg')}[/bold green]")
            break

        while True:
            console.print(f"\n[bold blue]{t('current_target', target)}[/bold blue]")
            console.print(f"  [1] [green]Fast[/green]       - {t('menu_fast')}")
            console.print(f"  [2] [yellow]Full[/yellow]       - {t('menu_full')}")
            console.print(f"  [3] [magenta]Aggressive[/magenta] - {t('menu_aggr')}")
            console.print(f"  [4] [red]Vuln[/red]       - {t('menu_vuln')}")
            console.print(f"  [5] [bold red]Pentest[/bold red]    - {t('menu_pent')}")
            console.print(f"  [6] [bold yellow]DoS Check[/bold yellow]  - {t('menu_dos')}")
            console.print(f"  [0] [white]Back[/white]       - {t('menu_back')}")

            choice = Prompt.ask(f"\n[bold cyan]{t('action_prompt')}[/bold cyan]",
                                choices=["0", "1", "2", "3", "4", "5", "6"], default="3")

            if choice == "0":
                break

            modes_map = {"1": "fast", "2": "full", "3": "aggressive", "4": "vuln", "5": "pentest", "6": "dos_check"}
            mode = modes_map[choice]

            save_report = Confirm.ask(f"[bold cyan]{t('save_prompt')}[/bold cyan]")
            output_file = Prompt.ask(f"[bold cyan]{t('file_prompt')}[/bold cyan]",
                                     default="network_report") if save_report else None

            console.print("\n")
            start_time = time.time()
            raw_scan_data = scan_target(target, mode)
            parsed_results = parse_results(raw_scan_data, target)
            generate_report(parsed_results, output_file)

            elapsed_time = time.time() - start_time
            logger.info(t("done_time", elapsed_time))

            Prompt.ask(f"\n[bold]{t('press_enter')}[/bold]")


def main():
    global CURRENT_LANG

    parser = argparse.ArgumentParser(description="ATTENTION Nmap Recon Scanner")
    parser.add_argument("target", nargs='?', help="IP-address or domain")
    parser.add_argument("-m", "--mode", choices=["fast", "full", "aggressive", "vuln", "pentest", "dos_check"],
                        default="aggressive")
    parser.add_argument("-o", "--output", help="Base filename for saving reports")
    parser.add_argument("-l", "--lang", choices=["en", "ru"], default="en", help="Language for output")

    args = parser.parse_args()

    if not args.target:
        interactive_mode()
    else:
        CURRENT_LANG = args.lang
        console.print(BANNER.format(t("banner_sub")))
        start_time = time.time()
        raw_scan_data = scan_target(args.target, args.mode)
        parsed_results = parse_results(raw_scan_data, args.target)
        generate_report(parsed_results, args.output)

        elapsed_time = time.time() - start_time
        logger.info(t("done_time", elapsed_time))


if __name__ == "__main__":
    main()